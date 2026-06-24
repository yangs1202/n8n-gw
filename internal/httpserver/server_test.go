package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangs1202/n8n-gw/internal/config"
	"github.com/yangs1202/n8n-gw/internal/n8n"
	oidcclient "github.com/yangs1202/n8n-gw/internal/oidc"
	"github.com/yangs1202/n8n-gw/internal/security"
	"github.com/yangs1202/n8n-gw/internal/session"
	"github.com/yangs1202/n8n-gw/internal/vault"
)

func TestPublicExecutionBypassesOIDC(t *testing.T) {
	var reached bool
	server := newTestServer(t, testDeps{
		publicProxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			if r.URL.Path != "/webhook/foo" {
				t.Fatalf("unexpected path %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("workflow"))
		}),
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/foo", strings.NewReader(`{"ok":true}`))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if !reached {
		t.Fatal("public proxy was not reached")
	}
	if rec.Code != http.StatusAccepted || rec.Body.String() != "workflow" {
		t.Fatalf("unexpected response %d %q", rec.Code, rec.Body.String())
	}
}

func TestDirectRestLoginBlocked(t *testing.T) {
	var reached bool
	server := newTestServer(t, testDeps{
		consoleProxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	req := httptest.NewRequest(http.MethodPost, "/rest/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if reached {
		t.Fatal("blocked login reached upstream proxy")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestProtectedRouteWithoutSessionRedirectsToOIDC(t *testing.T) {
	server := newTestServer(t, testDeps{})
	req := httptest.NewRequest(http.MethodGet, "/workflows?x=1", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/login?return_to=") {
		t.Fatalf("unexpected location %q", loc)
	}
}

func TestProtectedRouteWithSessionAndBridgeCookieProxies(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	var reached bool
	server := newTestServer(t, testDeps{
		sessions: store,
		consoleProxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "/workflows", nil)
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: security.N8NBridgeCookieName, Value: "1"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if !reached {
		t.Fatal("console proxy was not reached")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestProtectedRouteFallsBackToValidSessionCookie(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	var reached bool
	server := newTestServer(t, testDeps{
		sessions: store,
		consoleProxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "/workflows", nil)
	req.AddCookie(&http.Cookie{Name: security.InsecureProxySessionCookieName, Value: "stale-session"})
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: security.N8NBridgeCookieName, Value: "1"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if !reached {
		t.Fatal("console proxy was not reached")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestProtectedRouteWithoutN8NCookieLogsInAndRedirects(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	creds := vault.NewMemoryStore()
	if err := creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	}); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			if emailOrLoginID != "n8n@example.com" || password != "pw" {
				t.Fatalf("unexpected n8n credential %s/%s", emailOrLoginID, password)
			}
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=abc; Domain=n8n.internal"}}, nil
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "/workflows", nil)
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 2 || strings.Contains(got[0], "Domain=") {
		t.Fatalf("unexpected rewritten cookie: %#v", got)
	}
}

func TestNativeLoginAliasWithSessionRefreshesN8NCookie(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	creds := vault.NewMemoryStore()
	if err := creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	}); err != nil {
		t.Fatal(err)
	}
	var loginCalled bool
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			loginCalled = true
			if emailOrLoginID != "n8n@example.com" || password != "pw" {
				t.Fatalf("unexpected n8n credential %s/%s", emailOrLoginID, password)
			}
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=fresh; Domain=n8n.internal"}}, nil
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "/signin?redirect=%2Fhome%2Fworkflows", nil)
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: security.N8NBridgeCookieName, Value: "1"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if !loginCalled {
		t.Fatal("n8n login was not called")
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/home/workflows" {
		t.Fatalf("unexpected response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookies := strings.Join(rec.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(cookies, "n8n-auth=fresh") || strings.Contains(cookies, "Domain=n8n.internal") {
		t.Fatalf("unexpected rewritten cookies: %s", cookies)
	}
	if !strings.Contains(cookies, security.N8NBridgeCookieName+"=1") {
		t.Fatalf("bridge cookie was not refreshed: %s", cookies)
	}
}

func TestNativeLoginAliasWithoutSessionStartsOIDC(t *testing.T) {
	server := newTestServer(t, testDeps{})
	req := httptest.NewRequest(http.MethodGet, "/signin?redirect=%2Fhome%2Fworkflows", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/login?return_to=") {
		t.Fatalf("unexpected location %q", loc)
	}
}

func TestAuthLoginWithNativeRedirectAndSessionRefreshesN8NCookie(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	creds := vault.NewMemoryStore()
	if err := creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	}); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=fresh"}}, nil
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect=%252Fhome%252Fworkflows", nil)
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/home/workflows" {
		t.Fatalf("unexpected response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !strings.Contains(strings.Join(rec.Header().Values("Set-Cookie"), "\n"), "n8n-auth=fresh") {
		t.Fatalf("n8n cookie was not refreshed: %#v", rec.Header().Values("Set-Cookie"))
	}
}

func TestAuthLoginWithReturnToAndSessionRefreshesN8NCookie(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	creds := vault.NewMemoryStore()
	if err := creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	}); err != nil {
		t.Fatal(err)
	}
	var loginCalled bool
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			loginCalled = true
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=fresh"}}, nil
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/login?return_to=%2Fworkflows", nil)
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if !loginCalled {
		t.Fatal("n8n login was not called")
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/workflows" {
		t.Fatalf("unexpected response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookies := strings.Join(rec.Header().Values("Set-Cookie"), "\n")
	if !strings.Contains(cookies, "n8n-auth=fresh") {
		t.Fatalf("n8n cookie was not refreshed: %s", cookies)
	}
}

func TestAuthLoginWithoutReturnToAndSessionUsesReferer(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	creds := vault.NewMemoryStore()
	if err := creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	}); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=fresh"}}, nil
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.Host = "proxy.example.com"
	req.Header.Set("Referer", "http://proxy.example.com/home/workflows")
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/home/workflows" {
		t.Fatalf("unexpected response %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestProtectedRouteRateLimitReturns429(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	creds := vault.NewMemoryStore()
	if err := creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	}); err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: http.StatusTooManyRequests}, n8n.ErrRateLimited
		}},
	})
	req := httptest.NewRequest(http.MethodGet, "/workflows", nil)
	req.AddCookie(&http.Cookie{Name: security.InsecureProxySessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", rec.Header().Get("Retry-After"))
	}
}

func TestAuthCallbackWithoutCredentialRedirectsToLink(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	server := newTestServer(t, testDeps{
		sessions: store,
		oidc: oidcclient.FakeClient{Identity: oidcclient.Identity{
			Issuer:  "issuer",
			Subject: "subject",
			Email:   "user@example.com",
		}},
	})
	state := startOIDCAndExtractState(t, server)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=ok", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/n8n-link" {
		t.Fatalf("unexpected callback response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("expected proxy session cookie")
	}
}

func TestAuthCallbackWithCredentialLogsIntoN8N(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	creds := vault.NewMemoryStore()
	_ = creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	})
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		oidc: oidcclient.FakeClient{Identity: oidcclient.Identity{
			Issuer:  "issuer",
			Subject: "subject",
			Email:   "user@example.com",
		}},
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=abc; Domain=n8n.internal"}}, nil
		}},
	})
	state := startOIDCAndExtractState(t, server)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=ok", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("unexpected callback response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) < 2 {
		t.Fatalf("expected proxy and n8n cookies, got %#v", cookies)
	}
}

func TestAuthCallbackRejectsSignoutReturnTo(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	creds := vault.NewMemoryStore()
	_ = creds.Put(context.Background(), vault.Credential{
		Issuer:            "issuer",
		Subject:           "subject",
		Email:             "user@example.com",
		N8NEmailOrLoginID: "n8n@example.com",
		N8NPassword:       "pw",
	})
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		oidc: oidcclient.FakeClient{Identity: oidcclient.Identity{
			Issuer:  "issuer",
			Subject: "subject",
			Email:   "user@example.com",
		}},
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=abc"}}, nil
		}},
	})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/signout", nil))
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	state := loc.Query().Get("state")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?state="+state+"&code=ok", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback redirected to %d %q, want 302 /", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLinkPostValidatesAndStoresCredential(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	if err := store.SetCSRF(context.Background(), sessionID, "csrf"); err != nil {
		t.Fatal(err)
	}
	creds := vault.NewMemoryStore()
	server := newTestServer(t, testDeps{
		sessions:    store,
		credentials: creds,
		n8n: n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=abc"}}, nil
		}},
	})
	body := strings.NewReader("csrf_token=csrf&n8n_email_or_login_id=n8n%40example.com&n8n_password=pw")
	req := httptest.NewRequest(http.MethodPost, "/n8n-link", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: security.ProxySessionCookieName, Value: sessionID})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("unexpected response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cred, err := creds.Get(context.Background(), "issuer", "subject")
	if err != nil {
		t.Fatalf("credential not stored: %v", err)
	}
	if cred.N8NEmailOrLoginID != "n8n@example.com" || cred.N8NPassword != "pw" {
		t.Fatalf("unexpected credential: %#v", cred)
	}
}

func TestLogoutClearsProxySessionAndRedirectsHome(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	server := newTestServer(t, testDeps{
		sessions: store,
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: security.InsecureProxySessionCookieName, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: "abc"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/" {
		t.Fatalf("unexpected logout location %q", loc)
	}
	if _, err := store.GetSession(context.Background(), sessionID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("session still exists after logout: %v", err)
	}
}

func TestN8NLogoutPreservesProxySessionAndRedirectsHome(t *testing.T) {
	store := session.NewMemoryStore(time.Hour, time.Minute)
	sessionID := createTestSession(t, store)
	var logoutCookie string
	server := newTestServer(t, testDeps{
		sessions: store,
		n8n: n8n.FakeClient{
			LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
				return n8n.LoginResult{StatusCode: 200, Cookies: []string{"n8n-auth=abc"}}, nil
			},
			LogoutFunc: func(ctx context.Context, cookieHeader string) (n8n.LogoutResult, error) {
				logoutCookie = cookieHeader
				return n8n.LogoutResult{StatusCode: 200, Cookies: []string{"n8n-auth=; Max-Age=0"}}, nil
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/rest/logout", nil)
	req.AddCookie(&http.Cookie{Name: security.InsecureProxySessionCookieName, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: "n8n-auth", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: security.N8NBridgeCookieName, Value: "1"})
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("unexpected n8n logout response %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := store.GetSession(context.Background(), sessionID); err != nil {
		t.Fatalf("proxy session was removed by n8n logout: %v", err)
	}
	if !strings.Contains(logoutCookie, "n8n-auth=abc") {
		t.Fatalf("n8n logout did not receive upstream cookie header %q", logoutCookie)
	}
	cookies := rec.Header().Values("Set-Cookie")
	if strings.Contains(strings.Join(cookies, "\n"), security.InsecureProxySessionCookieName+"=") {
		t.Fatalf("n8n logout should not clear proxy session cookies: %#v", cookies)
	}
	if !strings.Contains(strings.Join(cookies, "\n"), security.N8NBridgeCookieName+"=") {
		t.Fatalf("n8n logout should clear bridge marker: %#v", cookies)
	}
}

func TestSignoutRouteDoesNotProxyToN8N(t *testing.T) {
	var proxied bool
	server := newTestServer(t, testDeps{
		consoleProxy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxied = true
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "/signout", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if proxied {
		t.Fatal("/signout reached n8n console proxy")
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("unexpected signout response %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func startOIDCAndExtractState(t *testing.T, server *Server) string {
	t.Helper()
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?return_to=/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("auth login status = %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("state missing from auth redirect")
	}
	return state
}

func createTestSession(t *testing.T, store session.Store) string {
	t.Helper()
	id, err := store.CreateSession(context.Background(), session.Session{
		Issuer:  "issuer",
		Subject: "subject",
		Email:   "user@example.com",
		Name:    "User",
		Linked:  true,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return id
}

type testDeps struct {
	sessions     session.Store
	credentials  vault.Store
	oidc         oidcclient.Client
	n8n          n8n.Client
	publicProxy  http.Handler
	consoleProxy http.Handler
}

func newTestServer(t *testing.T, deps testDeps) *Server {
	t.Helper()
	publicURL, _ := url.Parse("http://proxy.example.com")
	upstreamURL, _ := url.Parse("http://n8n.internal:5678")
	if deps.sessions == nil {
		deps.sessions = session.NewMemoryStore(time.Hour, time.Minute)
	}
	if deps.credentials == nil {
		deps.credentials = vault.NewMemoryStore()
	}
	if deps.oidc == nil {
		deps.oidc = oidcclient.FakeClient{Identity: oidcclient.Identity{Issuer: "issuer", Subject: "subject", Email: "user@example.com"}}
	}
	if deps.n8n == nil {
		deps.n8n = n8n.FakeClient{LoginFunc: func(ctx context.Context, emailOrLoginID, password string) (n8n.LoginResult, error) {
			return n8n.LoginResult{StatusCode: 200, Body: []byte(`{"id":"u"}`), Cookies: []string{"n8n-auth=abc"}}, nil
		}}
	}
	if deps.publicProxy == nil {
		deps.publicProxy = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "n8n 404")
		})
	}
	if deps.consoleProxy == nil {
		deps.consoleProxy = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "console")
		})
	}
	return New(Dependencies{
		Config: config.Config{
			PublicBaseURL:            publicURL,
			N8NUpstreamURL:           upstreamURL,
			SessionTTL:               time.Hour,
			OIDCStateTTL:             time.Minute,
			ConsoleProxyTimeout:      time.Second,
			PublicExecutionTimeout:   time.Second,
			PublicExecutionBodyLimit: 1024,
			PublicBypassPrefixes:     []string{"/webhook/", "/webhook-test/", "/webhook-waiting/", "/form/", "/form-test/", "/forms/", "/forms-test/"},
			CookieSecure:             false,
			LogLevel:                 "error",
		},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sessions:     deps.sessions,
		Credentials:  deps.credentials,
		OIDC:         deps.oidc,
		N8N:          deps.n8n,
		PublicProxy:  deps.publicProxy,
		ConsoleProxy: deps.consoleProxy,
	})
}
