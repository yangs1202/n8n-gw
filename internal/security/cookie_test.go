package security

import (
	"net/http"
	"testing"
)

func TestRewriteSetCookie(t *testing.T) {
	got := RewriteSetCookie("n8n-auth=abc; Domain=n8n.internal; Path=/; HttpOnly; SameSite=None", true)
	want := "n8n-auth=abc; Path=/; HttpOnly; SameSite=None; Secure"
	if got != want {
		t.Fatalf("RewriteSetCookie() = %q, want %q", got, want)
	}

	got = RewriteSetCookie("n8n-auth=abc; Max-Age=60; Priority=High", true)
	want = "n8n-auth=abc; Max-Age=60; Priority=High; Path=/; Secure; SameSite=Lax"
	if got != want {
		t.Fatalf("RewriteSetCookie() = %q, want %q", got, want)
	}

	got = RewriteSetCookie("n8n-auth=abc; Secure; SameSite=None", false)
	want = "n8n-auth=abc; SameSite=Lax; Path=/"
	if got != want {
		t.Fatalf("RewriteSetCookie() = %q, want %q", got, want)
	}
}

func TestHasN8NBridgeCookie(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: ProxySessionCookieName, Value: "proxy"})
	if HasN8NBridgeCookie(req) {
		t.Fatal("expected proxy cookie alone not to count as bridge cookie")
	}
	req.AddCookie(&http.Cookie{Name: InsecureProxySessionCookieName, Value: "proxy"})
	if HasN8NBridgeCookie(req) {
		t.Fatal("expected insecure proxy cookie alone not to count as bridge cookie")
	}
	req.AddCookie(&http.Cookie{Name: N8NBridgeCookieName, Value: "1"})
	if !HasN8NBridgeCookie(req) {
		t.Fatal("expected bridge marker to count as bridge cookie")
	}
}

func TestProxySessionCookiesIncludeSecureFallback(t *testing.T) {
	cookies := ProxySessionCookies("session-id", true, 3600)
	if len(cookies) != 2 {
		t.Fatalf("len = %d, want 2", len(cookies))
	}
	if cookies[0].Name != ProxySessionCookieName || cookies[1].Name != InsecureProxySessionCookieName {
		t.Fatalf("unexpected cookie names: %s, %s", cookies[0].Name, cookies[1].Name)
	}
	for _, cookie := range cookies {
		if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" {
			t.Fatalf("unexpected cookie attributes: %#v", cookie)
		}
	}

	cookies = ProxySessionCookies("session-id", false, 3600)
	if len(cookies) != 1 || cookies[0].Name != InsecureProxySessionCookieName || cookies[0].Secure {
		t.Fatalf("unexpected insecure cookie set: %#v", cookies)
	}
}

func TestClearProxySessionCookiesClearsSecureFallbacks(t *testing.T) {
	cookies := ClearProxySessionCookies(true)
	names := map[string]int{}
	for _, cookie := range cookies {
		names[cookie.Name]++
		if cookie.MaxAge != -1 || cookie.Path != "/" {
			t.Fatalf("unexpected clear cookie attributes: %#v", cookie)
		}
	}
	if names[ProxySessionCookieName] != 1 || names[InsecureProxySessionCookieName] != 2 {
		t.Fatalf("unexpected clear cookie names: %#v", names)
	}
}
