package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/yangs1202/n8n-gw/internal/security"
)

type ReverseProxy struct {
	handler *httputil.ReverseProxy
	timeout time.Duration
}

func New(upstream *url.URL, timeout time.Duration, forceSecureCookies bool) *ReverseProxy {
	return NewWithPublicBaseAndErrorCallback(upstream, nil, timeout, forceSecureCookies, nil)
}

func NewWithPublicBase(upstream, publicBase *url.URL, timeout time.Duration, forceSecureCookies bool) *ReverseProxy {
	return NewWithPublicBaseAndErrorCallback(upstream, publicBase, timeout, forceSecureCookies, nil)
}

func NewWithPublicBaseAndErrorCallback(upstream, publicBase *url.URL, timeout time.Duration, forceSecureCookies bool, onError func(error)) *ReverseProxy {
	director := func(req *http.Request) {
		originalHost := req.Host
		originalScheme := forwardedProto(req)
		if publicBase != nil {
			originalHost = publicBase.Host
			originalScheme = publicBase.Scheme
		}

		req.URL.Scheme = upstream.Scheme
		req.URL.Host = upstream.Host
		req.Host = upstream.Host
		if upstream.Path != "" && upstream.Path != "/" {
			req.URL.Path = singleJoiningSlash(upstream.Path, req.URL.Path)
		}

		req.Header.Set("X-Forwarded-Host", originalHost)
		req.Header.Set("X-Forwarded-Proto", originalScheme)
		appendXForwardedFor(req)
	}

	rp := &httputil.ReverseProxy{
		Director: director,
		ModifyResponse: func(resp *http.Response) error {
			security.RewriteSetCookies(resp.Header, forceSecureCookies)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if onError != nil {
				onError(err)
			}
			status := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			http.Error(w, fmt.Sprintf("upstream error: %s", http.StatusText(status)), status)
		},
	}

	return &ReverseProxy{handler: rp, timeout: timeout}
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}
	p.handler.ServeHTTP(w, r.WithContext(ctx))
}

func forwardedProto(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.Split(proto, ",")[0]
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func appendXForwardedFor(req *http.Request) {
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		clientIP = req.RemoteAddr
	}
	prior := req.Header.Get("X-Forwarded-For")
	if prior == "" {
		req.Header.Set("X-Forwarded-For", clientIP)
		return
	}
	req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

type BodyLimitMiddleware struct {
	Next  http.Handler
	Limit int64
}

func (m BodyLimitMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.Limit > 0 && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, m.Limit)
	}
	m.Next.ServeHTTP(w, r)
}

func DrainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1024))
	_ = body.Close()
}
