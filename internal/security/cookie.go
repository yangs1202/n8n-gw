package security

import (
	"net/http"
	"strings"
)

const ProxySessionCookieName = "__Host-n8np_session"
const InsecureProxySessionCookieName = "n8np_session"
const N8NBridgeCookieName = "n8np_n8n_bridge"

func ProxySessionCookieNameForSecure(secure bool) string {
	if secure {
		return ProxySessionCookieName
	}
	return InsecureProxySessionCookieName
}

func ProxySessionCookie(sessionID string, secure bool, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     ProxySessionCookieNameForSecure(secure),
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: true,
		SameSite: sameSiteForSessionCookie(secure),
	}
}

func ProxySessionCookies(sessionID string, secure bool, maxAge int) []*http.Cookie {
	cookies := []*http.Cookie{ProxySessionCookie(sessionID, secure, maxAge)}
	if secure {
		cookies = append(cookies, &http.Cookie{
			Name:     InsecureProxySessionCookieName,
			Value:    sessionID,
			Path:     "/",
			MaxAge:   maxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: sameSiteForSessionCookie(secure),
		})
	}
	return cookies
}

func ClearProxySessionCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     ProxySessionCookieNameForSecure(secure),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		HttpOnly: true,
		SameSite: sameSiteForSessionCookie(secure),
	}
}

func ClearProxySessionCookies(secure bool) []*http.Cookie {
	cookies := []*http.Cookie{ClearProxySessionCookie(secure)}
	if secure {
		cookies = append(cookies, &http.Cookie{
			Name:     InsecureProxySessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: sameSiteForSessionCookie(secure),
		})
	}
	cookies = append(cookies, ClearProxySessionCookie(false))
	return cookies
}

func N8NBridgeCookie(secure bool, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     N8NBridgeCookieName,
		Value:    "1",
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   secure,
		HttpOnly: true,
		SameSite: sameSiteForSessionCookie(secure),
	}
}

func ClearN8NBridgeCookie(secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     N8NBridgeCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		HttpOnly: true,
		SameSite: sameSiteForSessionCookie(secure),
	}
}

func sameSiteForSessionCookie(secure bool) http.SameSite {
	if secure {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

func RewriteSetCookie(raw string, forceSecure bool) string {
	parts := splitCookieParts(raw)
	if len(parts) == 0 {
		return raw
	}

	out := []string{strings.TrimSpace(parts[0])}
	hasPath := false
	hasSecure := false
	hasSameSite := false

	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if idx := strings.Index(trimmed, "="); idx >= 0 {
			key = strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		}
		switch key {
		case "domain":
			continue
		case "path":
			hasPath = true
		case "secure":
			hasSecure = true
			if !forceSecure {
				continue
			}
		case "samesite":
			if !forceSecure && sameSiteValue(trimmed) == "none" {
				hasSameSite = true
				out = append(out, "SameSite=Lax")
				continue
			}
			hasSameSite = true
		}
		out = append(out, trimmed)
	}

	if !hasPath {
		out = append(out, "Path=/")
	}
	if forceSecure && !hasSecure {
		out = append(out, "Secure")
	}
	if !hasSameSite {
		out = append(out, "SameSite=Lax")
	}

	return strings.Join(out, "; ")
}

func sameSiteValue(attr string) string {
	idx := strings.Index(attr, "=")
	if idx < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(attr[idx+1:]))
}

func RewriteSetCookies(headers http.Header, forceSecure bool) {
	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	headers.Del("Set-Cookie")
	for _, cookie := range cookies {
		headers.Add("Set-Cookie", RewriteSetCookie(cookie, forceSecure))
	}
}

func HasN8NBridgeCookie(r *http.Request) bool {
	cookie, err := r.Cookie(N8NBridgeCookieName)
	return err == nil && cookie.Value == "1"
}

func SanitizedUpstreamCookieHeader(raw string) string {
	parts := strings.Split(raw, ";")
	values := map[string]string{}
	var order []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(trimmed[:idx])
		if isProxyCookieName(name) {
			continue
		}
		if _, ok := values[name]; !ok {
			order = append(order, name)
		}
		values[name] = strings.TrimSpace(trimmed[idx+1:])
	}

	out := make([]string, 0, len(order))
	for _, name := range order {
		out = append(out, name+"="+values[name])
	}
	return strings.Join(out, "; ")
}

func isProxyCookieName(name string) bool {
	switch name {
	case ProxySessionCookieName, InsecureProxySessionCookieName, N8NBridgeCookieName:
		return true
	default:
		return false
	}
}

func splitCookieParts(raw string) []string {
	var parts []string
	start := 0
	inExpires := false
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case ';':
			inExpires = false
			parts = append(parts, raw[start:i])
			start = i + 1
		case ',':
			if inExpires {
				continue
			}
		default:
			if i >= start+8 && strings.EqualFold(strings.TrimSpace(raw[start:i+1]), "expires") {
				inExpires = true
			}
		}
	}
	parts = append(parts, raw[start:])
	return parts
}
