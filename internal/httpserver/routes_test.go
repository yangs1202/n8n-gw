package httpserver

import (
	"net/http"
	"testing"
)

func TestClassifyRoute(t *testing.T) {
	prefixes := []string{"/webhook/", "/webhook-test/", "/webhook-waiting/", "/form/", "/form-test/", "/forms/", "/forms-test/"}
	tests := []struct {
		name   string
		method string
		path   string
		want   RouteClass
	}{
		{"auth login", http.MethodGet, "/auth/login", RouteInternal},
		{"auth callback", http.MethodGet, "/auth/callback", RouteInternal},
		{"link", http.MethodGet, "/n8n-link", RouteInternal},
		{"webhook", http.MethodPost, "/webhook/foo", RoutePublicExecution},
		{"webhook exact", http.MethodPost, "/webhook", RoutePublicExecution},
		{"webhook test", http.MethodGet, "/webhook-test/foo", RoutePublicExecution},
		{"webhook waiting", http.MethodPost, "/webhook-waiting/foo", RoutePublicExecution},
		{"form", http.MethodGet, "/form/foo", RoutePublicExecution},
		{"form test", http.MethodPost, "/form-test/foo", RoutePublicExecution},
		{"forms", http.MethodGet, "/forms/foo", RoutePublicExecution},
		{"forms test", http.MethodPost, "/forms-test/foo", RoutePublicExecution},
		{"blocked login", http.MethodPost, "/rest/login", RouteBlockedNativeLogin},
		{"proxy logout", http.MethodPost, "/rest/logout", RouteInternal},
		{"n8n signout route", http.MethodGet, "/signout", RouteInternal},
		{"encoded blocked login", http.MethodPost, "/rest%2flogin", RouteBlockedNativeLogin},
		{"cleaned blocked login", http.MethodPost, "//rest/../rest/login", RouteBlockedNativeLogin},
		{"signin", http.MethodGet, "/signin", RouteNativeLoginAlias},
		{"workflows", http.MethodGet, "/workflows", RouteProtectedConsole},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyRoute(tt.method, tt.path, prefixes); got != tt.want {
				t.Fatalf("ClassifyRoute() = %s, want %s", got, tt.want)
			}
		})
	}
}
