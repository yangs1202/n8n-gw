package vault

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
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

func TestIsVaultAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "forbidden response",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusForbidden},
			want: true,
		},
		{
			name: "unauthorized response",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusUnauthorized},
			want: true,
		},
		{
			name: "not found response",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusNotFound},
			want: false,
		},
		{
			name: "permission denied text",
			err:  errors.New("permission denied"),
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isVaultAuthError(tc.err); got != tc.want {
				t.Fatalf("isVaultAuthError() = %v, want %v", got, tc.want)
			}
		})
	}
}
