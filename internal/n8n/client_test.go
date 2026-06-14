package n8n

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestClientLoginPayloadAndCookie(t *testing.T) {
	var payload map[string]string
	var gotUserAgent string
	var gotForwardedFor string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/login" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotUserAgent = r.Header.Get("User-Agent")
		gotForwardedFor = r.Header.Get("X-Forwarded-For")
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Add("Set-Cookie", "n8n-auth=abc; Domain=n8n.internal")
		_, _ = w.Write([]byte(`{"id":"user"}`))
	}))
	defer upstream.Close()

	parsed, _ := url.Parse(upstream.URL)
	client := NewClient(parsed, time.Second)
	headers := http.Header{}
	headers.Set("User-Agent", "browser-agent")
	headers.Set("X-Forwarded-For", "10.0.0.1")
	result, err := client.Login(context.Background(), "n8n@example.com", "pw", headers)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if payload["emailOrLdapLoginId"] != "n8n@example.com" || payload["password"] != "pw" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if len(result.Cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(result.Cookies))
	}
	if gotUserAgent != "browser-agent" || gotForwardedFor != "10.0.0.1" {
		t.Fatalf("forwarded headers were not preserved: ua=%q xff=%q", gotUserAgent, gotForwardedFor)
	}
}
