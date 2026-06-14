package httpserver

import (
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
)

type RouteClass string

const (
	RouteInternal           RouteClass = "internal"
	RoutePublicExecution    RouteClass = "public_execution"
	RouteBlockedNativeLogin RouteClass = "blocked_native_login"
	RouteNativeLoginAlias   RouteClass = "native_login_alias"
	RouteProtectedConsole   RouteClass = "protected_console"
)

func ClassifyRoute(method, rawPath string, publicPrefixes []string) RouteClass {
	path := CleanPath(rawPath)
	switch {
	case isInternalPath(path):
		return RouteInternal
	case method == http.MethodPost && path == "/rest/logout":
		return RouteInternal
	case isPublicBypassPath(path, publicPrefixes):
		return RoutePublicExecution
	case method == http.MethodPost && path == "/rest/login":
		return RouteBlockedNativeLogin
	case method == http.MethodGet && (path == "/signin" || path == "/login"):
		return RouteNativeLoginAlias
	default:
		return RouteProtectedConsole
	}
}

func CleanPath(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	unescaped, err := url.PathUnescape(rawPath)
	if err != nil {
		unescaped = rawPath
	}
	if !strings.HasPrefix(unescaped, "/") {
		unescaped = "/" + unescaped
	}
	cleaned := pathpkg.Clean(unescaped)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func isInternalPath(path string) bool {
	if path == "/n8n-link" || path == "/signout" || path == "/healthz" || path == "/readyz" || path == "/metrics" {
		return true
	}
	return strings.HasPrefix(path, "/auth/")
}

func isPublicBypassPath(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		base := strings.TrimSuffix(prefix, "/")
		if path == base || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
