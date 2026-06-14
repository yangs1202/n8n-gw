package vault

import (
	"strings"
	"testing"
)

func TestPathForHashesIssuerAndSubject(t *testing.T) {
	issuer := "https://idp.example.com"
	subject := "subject/with/slash"
	got := PathFor("n8n-gw/users", issuer, subject)
	if strings.Contains(got, issuer) || strings.Contains(got, subject) {
		t.Fatalf("path contains raw issuer or subject: %s", got)
	}
	if got != PathFor("n8n-gw/users", issuer, subject) {
		t.Fatal("same issuer and subject should produce stable path")
	}
	if got == PathFor("n8n-gw/users", issuer, "other") {
		t.Fatal("different subject should produce different path")
	}
	if got == PathFor("n8n-gw/users", "https://other.example.com", subject) {
		t.Fatal("different issuer should produce different path")
	}
}
