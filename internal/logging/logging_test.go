package logging

import "testing"

func TestRedactKeyValue(t *testing.T) {
	for _, key := range []string{"password", "n8n_password", "Authorization", "Cookie", "Set-Cookie", "id_token", "access_token", "refresh_token", "code", "csrf_token"} {
		if got := RedactKeyValue(key, "secret"); got != "[REDACTED]" {
			t.Fatalf("RedactKeyValue(%q) = %v", key, got)
		}
	}
	if got := RedactKeyValue("path", "/workflows"); got != "/workflows" {
		t.Fatalf("non-sensitive key was redacted: %v", got)
	}
}
