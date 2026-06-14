package httpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yangs1202/n8n-gw/internal/config"
	"github.com/yangs1202/n8n-gw/internal/n8n"
	oidcclient "github.com/yangs1202/n8n-gw/internal/oidc"
	proxypkg "github.com/yangs1202/n8n-gw/internal/proxy"
	"github.com/yangs1202/n8n-gw/internal/security"
	"github.com/yangs1202/n8n-gw/internal/session"
	"github.com/yangs1202/n8n-gw/internal/vault"
)

type Dependencies struct {
	Config       config.Config
	Logger       *slog.Logger
	Sessions     session.Store
	Credentials  vault.Store
	OIDC         oidcclient.Client
	N8N          n8n.Client
	PublicProxy  http.Handler
	ConsoleProxy http.Handler
}

type Server struct {
	cfg          config.Config
	logger       *slog.Logger
	sessions     session.Store
	credentials  vault.Store
	oidc         oidcclient.Client
	n8n          n8n.Client
	publicProxy  http.Handler
	consoleProxy http.Handler
	metrics      *metrics
	metricsHTTP  http.Handler
}

func New(deps Dependencies) *Server {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	publicProxy := deps.PublicProxy
	if deps.PublicProxy == nil {
		publicProxy = proxypkg.BodyLimitMiddleware{
			Next: proxypkg.NewWithPublicBaseAndErrorCallback(
				deps.Config.N8NUpstreamURL,
				deps.Config.PublicBaseURL,
				deps.Config.PublicExecutionTimeout,
				deps.Config.CookieSecure,
				func(error) { m.upstreamErrors.WithLabelValues(string(RoutePublicExecution)).Inc() },
			),
			Limit: deps.Config.PublicExecutionBodyLimit,
		}
	}
	consoleProxy := deps.ConsoleProxy
	if deps.ConsoleProxy == nil {
		consoleProxy = proxypkg.NewWithPublicBaseAndErrorCallback(
			deps.Config.N8NUpstreamURL,
			deps.Config.PublicBaseURL,
			deps.Config.ConsoleProxyTimeout,
			deps.Config.CookieSecure,
			func(error) { m.upstreamErrors.WithLabelValues(string(RouteProtectedConsole)).Inc() },
		)
	}
	return &Server{
		cfg:          deps.Config,
		logger:       logger,
		sessions:     deps.Sessions,
		credentials:  deps.Credentials,
		oidc:         deps.OIDC,
		n8n:          deps.N8N,
		publicProxy:  publicProxy,
		consoleProxy: consoleProxy,
		metrics:      m,
		metricsHTTP:  promhttp.HandlerFor(reg, promhttp.HandlerOpts{}),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := requestID(r)
	ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
	r = r.WithContext(ctx)
	w.Header().Set("X-Request-Id", requestID)
	s.normalizeForwardedHeaders(r)

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	routeClass := ClassifyRoute(r.Method, r.URL.Path, s.cfg.PublicBypassPrefixes)
	defer func() {
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rec.status)
		s.metrics.requests.WithLabelValues(string(routeClass), status).Inc()
		s.metrics.duration.WithLabelValues(string(routeClass)).Observe(duration)
		s.logger.Info("request completed",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"route_class", string(routeClass),
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	defer func() {
		if recovered := recover(); recovered != nil {
			s.logger.Error("panic recovered", "request_id", requestID, "error", recovered)
			http.Error(rec, "internal server error", http.StatusInternalServerError)
		}
	}()

	applySecurityHeaders(rec.Header(), routeClass == RouteInternal || routeClass == RouteBlockedNativeLogin || routeClass == RouteNativeLoginAlias)

	switch routeClass {
	case RouteInternal:
		s.serveInternal(rec, r)
	case RoutePublicExecution:
		s.metrics.publicInflight.Inc()
		defer s.metrics.publicInflight.Dec()
		s.publicProxy.ServeHTTP(rec, r)
	case RouteBlockedNativeLogin:
		http.NotFound(rec, r)
	case RouteNativeLoginAlias:
		s.handleNativeLoginAlias(rec, r)
	case RouteProtectedConsole:
		s.serveProtected(rec, r)
	default:
		http.NotFound(rec, r)
	}
}

func (s *Server) serveInternal(w http.ResponseWriter, r *http.Request) {
	path := CleanPath(r.URL.Path)
	switch {
	case path == "/healthz" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case path == "/readyz" && r.Method == http.MethodGet:
		s.handleReady(w, r)
	case path == "/metrics" && r.Method == http.MethodGet:
		s.metricsHTTP.ServeHTTP(w, r)
	case path == "/auth/login" && r.Method == http.MethodGet:
		s.handleAuthLogin(w, r)
	case path == "/auth/callback" && r.Method == http.MethodGet:
		s.handleAuthCallback(w, r)
	case path == "/auth/logout" && r.Method == http.MethodPost:
		s.handleProxyLogout(w, r)
	case path == "/rest/logout" && r.Method == http.MethodPost:
		s.handleN8NLogout(w, r)
	case path == "/signout" && r.Method == http.MethodGet:
		s.handleN8NSignout(w, r)
	case path == "/n8n-link" && r.Method == http.MethodGet:
		s.handleLinkGet(w, r)
	case path == "/n8n-link" && r.Method == http.MethodPost:
		s.handleLinkPost(w, r)
	case path == "/n8n-link" && r.Method == http.MethodDelete:
		s.handleLinkDelete(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("redirect") != "" || r.URL.Query().Get("redirect_to") != "" || r.URL.Query().Get("return_to") == "" {
		_, sess, hadCookie, err := s.lookupSessionFromCookies(r)
		if err == nil {
			s.loginAndRedirectTo(w, r, sess, nativeLoginReturnTo(r))
			return
		}
		if hadCookie && errors.Is(err, session.ErrNotFound) {
			s.clearProxySessionCookies(w)
		} else if err != nil {
			s.writeError(w, r, http.StatusServiceUnavailable, "session_store_unavailable")
			return
		}
	}
	returnTo := r.URL.Query().Get("return_to")
	if !security.ValidReturnTo(returnTo) || isForbiddenReturnPath(returnTo) {
		returnTo = "/"
	}
	state, err := security.RandomBase64URL(32)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "random_failed")
		return
	}
	nonce, err := security.RandomBase64URL(32)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "random_failed")
		return
	}
	verifier, err := security.RandomBase64URL(32)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, "random_failed")
		return
	}
	if err := s.sessions.StoreOIDCState(r.Context(), state, session.OIDCState{
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnTo:     returnTo,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "session_store_unavailable")
		return
	}
	s.metrics.oidcLogin.WithLabelValues("started").Inc()
	http.Redirect(w, r, s.oidc.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	stateValue := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if stateValue == "" || code == "" {
		s.metrics.oidcLogin.WithLabelValues("bad_callback").Inc()
		s.writeError(w, r, http.StatusBadRequest, "invalid_oidc_callback")
		return
	}
	stored, err := s.sessions.TakeOIDCState(r.Context(), stateValue)
	if err != nil {
		s.metrics.oidcLogin.WithLabelValues("invalid_state").Inc()
		s.writeError(w, r, http.StatusBadRequest, "invalid_oidc_state")
		return
	}
	identity, err := s.oidc.Exchange(r.Context(), code, stored.Nonce, stored.CodeVerifier)
	if err != nil {
		s.metrics.oidcLogin.WithLabelValues("exchange_failed").Inc()
		s.writeError(w, r, http.StatusUnauthorized, "oidc_exchange_failed")
		return
	}
	sess := session.Session{
		Issuer:  identity.Issuer,
		Subject: identity.Subject,
		Email:   identity.Email,
		Name:    identity.Name,
		Linked:  false,
	}
	sessionID, err := s.sessions.CreateSession(r.Context(), sess)
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "session_store_unavailable")
		return
	}
	s.writeProxySessionCookies(w, sessionID)

	cred, err := s.getCredential(r.Context(), identity.Issuer, identity.Subject)
	if errors.Is(err, vault.ErrNotFound) {
		http.Redirect(w, r, "/n8n-link", http.StatusFound)
		return
	}
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable")
		return
	}

	result, err := s.n8n.Login(r.Context(), cred.N8NEmailOrLoginID, cred.N8NPassword, s.n8nLoginHeaders(r))
	if err != nil {
		s.metrics.n8nLogin.WithLabelValues(loginResultLabel(err)).Inc()
		s.handleN8NLoginError(w, r, err, true)
		return
	}
	s.metrics.n8nLogin.WithLabelValues("success").Inc()
	sess.Linked = true
	_ = s.sessions.SaveSession(r.Context(), sessionID, sess)
	s.writeN8NCookies(w, result.Cookies)
	http.SetCookie(w, security.N8NBridgeCookie(s.cfg.CookieSecure, int(s.cfg.SessionTTL.Seconds())))
	http.Redirect(w, r, safeReturnTo(stored.ReturnTo), http.StatusFound)
}

func (s *Server) handleProxyLogout(w http.ResponseWriter, r *http.Request) {
	for _, id := range s.sessionCookieIDs(r) {
		_ = s.sessions.DeleteSession(r.Context(), id)
	}
	result, _ := s.n8n.Logout(r.Context(), r.Header.Get("Cookie"))
	s.writeN8NCookies(w, result.Cookies)
	s.clearProxySessionCookies(w)
	http.SetCookie(w, security.ClearN8NBridgeCookie(s.cfg.CookieSecure))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleN8NLogout(w http.ResponseWriter, r *http.Request) {
	result, _ := s.n8n.Logout(r.Context(), r.Header.Get("Cookie"))
	s.writeN8NCookies(w, result.Cookies)
	http.SetCookie(w, security.ClearN8NBridgeCookie(s.cfg.CookieSecure))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleN8NSignout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, security.ClearN8NBridgeCookie(s.cfg.CookieSecure))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLinkGet(w http.ResponseWriter, r *http.Request) {
	sessionID, sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	token, err := s.sessions.GetCSRF(r.Context(), sessionID)
	if errors.Is(err, session.ErrNotFound) {
		token, err = security.NewCSRFToken()
		if err == nil {
			err = s.sessions.SetCSRF(r.Context(), sessionID, token)
		}
	}
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "csrf_unavailable")
		return
	}
	_, linkedErr := s.getCredential(r.Context(), sess.Issuer, sess.Subject)
	if linkedErr != nil && !errors.Is(linkedErr, vault.ErrNotFound) {
		s.writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable")
		return
	}
	data := linkPageData{
		Email:      sess.Email,
		Name:       sess.Name,
		CSRFToken:  token,
		Linked:     linkedErr == nil,
		Error:      r.URL.Query().Get("error"),
		ReLinkHint: r.URL.Query().Get("error") == "relink_required",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := linkTemplate.Execute(w, data); err != nil {
		s.logger.Error("render link page failed", "error", err)
	}
}

func (s *Server) handleLinkPost(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("_method") == "DELETE" {
		s.handleLinkDelete(w, r)
		return
	}
	sessionID, sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.validateCSRF(w, r, sessionID) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_form")
		return
	}
	loginID := strings.TrimSpace(r.FormValue("n8n_email_or_login_id"))
	password := r.FormValue("n8n_password")
	if loginID == "" || password == "" {
		s.writeError(w, r, http.StatusBadRequest, "missing_n8n_credential")
		return
	}

	result, err := s.n8n.Login(r.Context(), loginID, password, s.n8nLoginHeaders(r))
	if err != nil {
		s.metrics.n8nLogin.WithLabelValues(loginResultLabel(err)).Inc()
		s.handleN8NLoginError(w, r, err, false)
		return
	}
	s.metrics.n8nLogin.WithLabelValues("success").Inc()

	if err := s.putCredential(r.Context(), vault.Credential{
		Issuer:            sess.Issuer,
		Subject:           sess.Subject,
		Email:             sess.Email,
		N8NEmailOrLoginID: loginID,
		N8NPassword:       password,
	}); err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable")
		return
	}

	sess.Linked = true
	_ = s.sessions.SaveSession(r.Context(), sessionID, sess)
	s.writeN8NCookies(w, result.Cookies)
	http.SetCookie(w, security.N8NBridgeCookie(s.cfg.CookieSecure, int(s.cfg.SessionTTL.Seconds())))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleLinkDelete(w http.ResponseWriter, r *http.Request) {
	sessionID, sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if !s.validateCSRF(w, r, sessionID) {
		return
	}
	if err := s.deleteCredential(r.Context(), sess.Issuer, sess.Subject); err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable")
		return
	}
	sess.Linked = false
	_ = s.sessions.SaveSession(r.Context(), sessionID, sess)
	http.Redirect(w, r, "/n8n-link", http.StatusFound)
}

func (s *Server) serveProtected(w http.ResponseWriter, r *http.Request) {
	_, sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}

	if CleanPath(r.URL.Path) == "/rest/login" && r.Method == http.MethodGet {
		s.handleCurrentUserBridge(w, r, sess)
		return
	}

	if !security.HasN8NBridgeCookie(r) {
		if s.loginAndRedirect(w, r, sess) {
			return
		}
		return
	}
	s.consoleProxy.ServeHTTP(w, r)
}

func (s *Server) handleNativeLoginAlias(w http.ResponseWriter, r *http.Request) {
	_, sess, hadCookie, err := s.lookupSessionFromCookies(r)
	if !hadCookie {
		s.redirectToLogin(w, r)
		return
	}
	if errors.Is(err, session.ErrNotFound) {
		s.clearProxySessionCookies(w)
		s.redirectToLogin(w, r)
		return
	}
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "session_store_unavailable")
		return
	}
	target := nativeLoginReturnTo(r)
	s.loginAndRedirectTo(w, r, sess, target)
}

func (s *Server) handleCurrentUserBridge(w http.ResponseWriter, r *http.Request, sess session.Session) {
	if security.HasN8NBridgeCookie(r) {
		current, err := s.n8n.CurrentUser(r.Context(), r.Header.Get("Cookie"))
		if err == nil && current.StatusCode >= 200 && current.StatusCode < 300 {
			s.writeN8NCookies(w, current.Cookies)
			if current.ContentType != "" {
				w.Header().Set("Content-Type", current.ContentType)
			} else {
				w.Header().Set("Content-Type", "application/json")
			}
			w.WriteHeader(current.StatusCode)
			_, _ = w.Write(current.Body)
			return
		}
	}

	cred, err := s.getCredential(r.Context(), sess.Issuer, sess.Subject)
	if errors.Is(err, vault.ErrNotFound) {
		http.Redirect(w, r, "/n8n-link", http.StatusFound)
		return
	}
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable")
		return
	}
	result, err := s.n8n.Login(r.Context(), cred.N8NEmailOrLoginID, cred.N8NPassword, s.n8nLoginHeaders(r))
	if err != nil {
		s.metrics.n8nLogin.WithLabelValues(loginResultLabel(err)).Inc()
		s.handleN8NLoginError(w, r, err, true)
		return
	}
	s.metrics.n8nLogin.WithLabelValues("success").Inc()
	s.writeN8NCookies(w, result.Cookies)
	http.SetCookie(w, security.N8NBridgeCookie(s.cfg.CookieSecure, int(s.cfg.SessionTTL.Seconds())))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Body)
}

func (s *Server) loginAndRedirect(w http.ResponseWriter, r *http.Request, sess session.Session) bool {
	return s.loginAndRedirectTo(w, r, sess, safeReturnTo(r.URL.RequestURI()))
}

func (s *Server) loginAndRedirectTo(w http.ResponseWriter, r *http.Request, sess session.Session, returnTo string) bool {
	cred, err := s.getCredential(r.Context(), sess.Issuer, sess.Subject)
	if errors.Is(err, vault.ErrNotFound) {
		http.Redirect(w, r, "/n8n-link", http.StatusFound)
		return true
	}
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable")
		return true
	}
	result, err := s.n8n.Login(r.Context(), cred.N8NEmailOrLoginID, cred.N8NPassword, s.n8nLoginHeaders(r))
	if err != nil {
		s.metrics.n8nLogin.WithLabelValues(loginResultLabel(err)).Inc()
		s.handleN8NLoginError(w, r, err, true)
		return true
	}
	s.metrics.n8nLogin.WithLabelValues("success").Inc()
	s.writeN8NCookies(w, result.Cookies)
	http.SetCookie(w, security.N8NBridgeCookie(s.cfg.CookieSecure, int(s.cfg.SessionTTL.Seconds())))
	http.Redirect(w, r, safeReturnTo(returnTo), http.StatusFound)
	return true
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	checks := map[string]string{}
	ok := true
	if err := s.sessions.Ping(ctx); err != nil {
		ok = false
		checks["redis"] = "error"
	} else {
		checks["redis"] = "ok"
	}
	if err := s.credentials.Ping(ctx); err != nil {
		ok = false
		checks["vault"] = "error"
	} else {
		checks["vault"] = "ok"
	}
	if err := s.n8n.Ping(ctx); err != nil {
		ok = false
		checks["n8n"] = "error"
	} else {
		checks["n8n"] = "ok"
	}
	if err := s.oidc.Ping(ctx); err != nil {
		ok = false
		checks["oidc"] = "error"
	} else {
		checks["oidc"] = "ok"
	}
	status := http.StatusOK
	if !ok {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ok": ok, "checks": checks})
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (string, session.Session, bool) {
	sessionID, sess, hadCookie, err := s.lookupSessionFromCookies(r)
	if !hadCookie {
		s.redirectToLogin(w, r)
		return "", session.Session{}, false
	}
	if errors.Is(err, session.ErrNotFound) {
		s.clearProxySessionCookies(w)
		s.redirectToLogin(w, r)
		return "", session.Session{}, false
	}
	if err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "session_store_unavailable")
		return "", session.Session{}, false
	}
	return sessionID, sess, true
}

func (s *Server) sessionID(r *http.Request) (string, bool) {
	ids := s.sessionCookieIDs(r)
	if len(ids) == 0 {
		return "", false
	}
	return ids[0], true
}

func (s *Server) lookupSessionFromCookies(r *http.Request) (string, session.Session, bool, error) {
	ids := s.sessionCookieIDs(r)
	if len(ids) == 0 {
		return "", session.Session{}, false, nil
	}
	for _, id := range ids {
		sess, err := s.sessions.GetSession(r.Context(), id)
		if err == nil {
			return id, sess, true, nil
		}
		if !errors.Is(err, session.ErrNotFound) {
			return "", session.Session{}, true, err
		}
	}
	return "", session.Session{}, true, session.ErrNotFound
}

func (s *Server) sessionCookieIDs(r *http.Request) []string {
	names := []string{security.InsecureProxySessionCookieName, security.ProxySessionCookieNameForSecure(s.cfg.CookieSecure), security.ProxySessionCookieName}
	seen := map[string]struct{}{}
	var ids []string
	for _, name := range names {
		for _, cookie := range r.Cookies() {
			if cookie.Name != name || cookie.Value == "" {
				continue
			}
			if _, ok := seen[cookie.Value]; ok {
				continue
			}
			seen[cookie.Value] = struct{}{}
			ids = append(ids, cookie.Value)
		}
	}
	return ids
}

func (s *Server) validateCSRF(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid_form")
		return false
	}
	expected, err := s.sessions.GetCSRF(r.Context(), sessionID)
	if err != nil {
		s.writeError(w, r, http.StatusForbidden, "csrf_invalid")
		return false
	}
	if !security.EqualToken(expected, r.FormValue("csrf_token")) {
		s.writeError(w, r, http.StatusForbidden, "csrf_invalid")
		return false
	}
	return true
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := safeReturnTo(r.URL.RequestURI())
	target := "/auth/login?return_to=" + url.QueryEscape(returnTo)
	http.Redirect(w, r, target, http.StatusFound)
}

func nativeLoginReturnTo(r *http.Request) string {
	for _, key := range []string{"redirect", "redirect_to", "return_to"} {
		value := r.URL.Query().Get(key)
		if returnTo, ok := validNativeReturnTo(value); ok {
			return returnTo
		}
	}
	if returnTo, ok := validRefererReturnTo(r); ok {
		return returnTo
	}
	return "/"
}

func validNativeReturnTo(value string) (string, bool) {
	candidate := value
	for i := 0; i < 3; i++ {
		if security.ValidReturnTo(candidate) && !isForbiddenReturnPath(candidate) && strings.HasPrefix(candidate, "/") {
			return candidate, true
		}
		unescaped, err := url.QueryUnescape(candidate)
		if err != nil || unescaped == candidate {
			break
		}
		candidate = unescaped
	}
	return "", false
}

func validRefererReturnTo(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Referer())
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host != r.Host {
		return "", false
	}
	value := parsed.RequestURI()
	if security.ValidReturnTo(value) && !isForbiddenReturnPath(value) {
		return value, true
	}
	return "", false
}

func (s *Server) writeN8NCookies(w http.ResponseWriter, cookies []string) {
	for _, cookie := range cookies {
		w.Header().Add("Set-Cookie", security.RewriteSetCookie(cookie, s.cfg.CookieSecure))
	}
}

func (s *Server) n8nLoginHeaders(r *http.Request) http.Header {
	headers := http.Header{}
	for _, name := range []string{"User-Agent", "Accept-Language"} {
		if value := r.Header.Get(name); value != "" {
			headers.Set(name, value)
		}
	}
	if clientIP := remoteIP(r.RemoteAddr); clientIP != "" {
		headers.Set("X-Forwarded-For", clientIP)
		headers.Set("X-Real-IP", clientIP)
	}
	headers.Set("X-Forwarded-Host", s.cfg.PublicBaseURL.Host)
	headers.Set("X-Forwarded-Proto", s.cfg.PublicBaseURL.Scheme)
	return headers
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func (s *Server) writeProxySessionCookies(w http.ResponseWriter, sessionID string) {
	for _, cookie := range security.ProxySessionCookies(sessionID, s.cfg.CookieSecure, int(s.cfg.SessionTTL.Seconds())) {
		http.SetCookie(w, cookie)
	}
}

func (s *Server) clearProxySessionCookies(w http.ResponseWriter) {
	for _, cookie := range security.ClearProxySessionCookies(s.cfg.CookieSecure) {
		http.SetCookie(w, cookie)
	}
}

func (s *Server) handleN8NLoginError(w http.ResponseWriter, r *http.Request, err error, redirectToRelink bool) {
	if errors.Is(err, n8n.ErrRateLimited) {
		w.Header().Set("Retry-After", "60")
		s.writeError(w, r, http.StatusTooManyRequests, "n8n_rate_limited")
		return
	}
	if redirectToRelink {
		http.Redirect(w, r, "/n8n-link?error=relink_required", http.StatusFound)
		return
	}
	s.writeError(w, r, http.StatusBadRequest, "invalid_n8n_credential")
}

func (s *Server) normalizeForwardedHeaders(r *http.Request) {
	if len(s.cfg.TrustedProxyCIDRs) == 0 || !remoteAddrTrusted(r.RemoteAddr, s.cfg.TrustedProxyCIDRs) {
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Host")
		r.Header.Del("X-Forwarded-Proto")
	}
}

func remoteAddrTrusted(remoteAddr string, cidrs []string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) getCredential(ctx context.Context, issuer, subject string) (vault.Credential, error) {
	cred, err := s.credentials.Get(ctx, issuer, subject)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			s.metrics.vaultOps.WithLabelValues("read", "not_found").Inc()
		} else {
			s.metrics.vaultOps.WithLabelValues("read", "error").Inc()
		}
		return vault.Credential{}, err
	}
	s.metrics.vaultOps.WithLabelValues("read", "success").Inc()
	return cred, nil
}

func (s *Server) putCredential(ctx context.Context, cred vault.Credential) error {
	if err := s.credentials.Put(ctx, cred); err != nil {
		s.metrics.vaultOps.WithLabelValues("write", "error").Inc()
		return err
	}
	s.metrics.vaultOps.WithLabelValues("write", "success").Inc()
	return nil
}

func (s *Server) deleteCredential(ctx context.Context, issuer, subject string) error {
	if err := s.credentials.Delete(ctx, issuer, subject); err != nil {
		s.metrics.vaultOps.WithLabelValues("delete", "error").Inc()
		return err
	}
	s.metrics.vaultOps.WithLabelValues("delete", "success").Inc()
	return nil
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code string) {
	if wantsJSON(r) {
		writeJSON(w, status, map[string]any{
			"error":      code,
			"request_id": RequestID(r.Context()),
		})
		return
	}
	http.Error(w, code, status)
}

func safeReturnTo(value string) string {
	if security.ValidReturnTo(value) && !isForbiddenReturnPath(value) {
		return value
	}
	return "/"
}

func isForbiddenReturnPath(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return true
	}
	switch CleanPath(parsed.Path) {
	case "/signout", "/signin", "/login", "/auth/logout", "/rest/logout":
		return true
	default:
		return false
	}
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func applySecurityHeaders(header http.Header, includeCSP bool) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Frame-Options", "SAMEORIGIN")
	if includeCSP {
		header.Set("Content-Security-Policy", "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'")
	}
}

func loginResultLabel(err error) string {
	switch {
	case errors.Is(err, n8n.ErrInvalidCredential):
		return "invalid_credential"
	case errors.Is(err, n8n.ErrMFARequired):
		return "mfa_required"
	case errors.Is(err, n8n.ErrRateLimited):
		return "rate_limited"
	default:
		return "error"
	}
}

type requestIDKey struct{}

func RequestID(ctx context.Context) string {
	if value, ok := ctx.Value(requestIDKey{}).(string); ok {
		return value
	}
	return ""
}

func requestID(r *http.Request) string {
	if incoming := strings.TrimSpace(r.Header.Get("X-Request-Id")); incoming != "" {
		return incoming
	}
	id, err := security.RandomBase64URL(16)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return "req_" + id
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

type metrics struct {
	requests       *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	oidcLogin      *prometheus.CounterVec
	n8nLogin       *prometheus.CounterVec
	vaultOps       *prometheus.CounterVec
	publicInflight prometheus.Gauge
	upstreamErrors *prometheus.CounterVec
}

func newMetrics(reg *prometheus.Registry) *metrics {
	factory := promauto.With(reg)
	m := &metrics{
		requests: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_proxy_requests_total",
			Help: "Total n8n proxy requests.",
		}, []string{"route_class", "status"}),
		duration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "n8n_proxy_request_duration_seconds",
			Help:    "n8n proxy request duration.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route_class"}),
		oidcLogin: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_proxy_oidc_login_total",
			Help: "OIDC login attempts.",
		}, []string{"result"}),
		n8nLogin: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_proxy_n8n_login_total",
			Help: "n8n login bridge attempts.",
		}, []string{"result"}),
		vaultOps: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_proxy_vault_operations_total",
			Help: "Vault operations.",
		}, []string{"operation", "result"}),
		publicInflight: factory.NewGauge(prometheus.GaugeOpts{
			Name: "n8n_proxy_public_execution_inflight",
			Help: "Inflight public execution requests.",
		}),
		upstreamErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "n8n_proxy_upstream_errors_total",
			Help: "Upstream errors.",
		}, []string{"route_class"}),
	}
	for _, routeClass := range []RouteClass{RouteInternal, RoutePublicExecution, RouteBlockedNativeLogin, RouteNativeLoginAlias, RouteProtectedConsole} {
		m.requests.WithLabelValues(string(routeClass), "200")
		m.duration.WithLabelValues(string(routeClass))
	}
	for _, result := range []string{"started", "success", "bad_callback", "invalid_state", "exchange_failed"} {
		m.oidcLogin.WithLabelValues(result)
	}
	for _, result := range []string{"success", "invalid_credential", "mfa_required", "rate_limited", "error"} {
		m.n8nLogin.WithLabelValues(result)
	}
	for _, operation := range []string{"read", "write", "delete"} {
		for _, result := range []string{"success", "not_found", "error"} {
			m.vaultOps.WithLabelValues(operation, result)
		}
	}
	for _, routeClass := range []RouteClass{RoutePublicExecution, RouteProtectedConsole} {
		m.upstreamErrors.WithLabelValues(string(routeClass))
	}
	return m
}

type linkPageData struct {
	Email      string
	Name       string
	CSRFToken  string
	Linked     bool
	Error      string
	ReLinkHint bool
}

var linkTemplate = template.Must(template.New("link").Parse(`<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>n8n account link</title>
  <style>
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f7f7f8;color:#18181b}
    main{max-width:420px;margin:8vh auto;padding:24px;background:white;border:1px solid #e4e4e7;border-radius:8px}
    label{display:block;margin:14px 0 6px;font-size:14px;font-weight:600}
    input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #d4d4d8;border-radius:6px;font-size:15px}
    button{margin-top:16px;width:100%;padding:10px 12px;border:0;border-radius:6px;background:#111827;color:white;font-weight:700;cursor:pointer}
    button.secondary{background:#b91c1c}
    p{line-height:1.5}
    .muted{color:#52525b;font-size:14px}
    .error{padding:10px 12px;background:#fef2f2;color:#991b1b;border:1px solid #fecaca;border-radius:6px}
  </style>
</head>
<body>
<main>
  <h1>n8n 계정 연결</h1>
  <p class="muted">{{if .Name}}{{.Name}} {{end}}{{.Email}}</p>
  {{if .ReLinkHint}}<p class="error">저장된 n8n 계정으로 로그인할 수 없습니다. 다시 연결하세요.</p>{{else if .Error}}<p class="error">요청을 처리할 수 없습니다.</p>{{end}}
  {{if .Linked}}<p class="muted">이미 연결된 n8n 계정이 있습니다. 새 값으로 다시 연결할 수 있습니다.</p>{{end}}
  <form method="post" action="/n8n-link">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <label for="n8n_email_or_login_id">n8n 이메일 또는 로그인 ID</label>
    <input id="n8n_email_or_login_id" name="n8n_email_or_login_id" autocomplete="username" required>
    <label for="n8n_password">n8n 비밀번호</label>
    <input id="n8n_password" name="n8n_password" type="password" autocomplete="current-password" required>
    <button type="submit">연결</button>
  </form>
  {{if .Linked}}
  <form method="post" action="/n8n-link">
    <input type="hidden" name="_method" value="DELETE">
    <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
    <button class="secondary" type="submit">연결 삭제</button>
  </form>
  {{end}}
</main>
</body>
</html>`))
