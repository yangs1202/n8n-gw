package security

import "testing"

func TestValidReturnTo(t *testing.T) {
	allowed := []string{"/", "/workflows", "/workflow/123?foo=bar"}
	for _, value := range allowed {
		if !ValidReturnTo(value) {
			t.Fatalf("expected %q to be allowed", value)
		}
	}

	rejected := []string{"", "https://evil.example.com", "//evil.example.com", `/\evil`, "/foo\nbar"}
	for _, value := range rejected {
		if ValidReturnTo(value) {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
