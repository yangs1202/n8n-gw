package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURL  string
}

type Identity struct {
	Issuer  string
	Subject string
	Email   string
	Name    string
}

type Client interface {
	AuthCodeURL(state, nonce, codeVerifier string) string
	Exchange(ctx context.Context, code, nonce, codeVerifier string) (Identity, error)
	Ping(ctx context.Context) error
}

type ProviderClient struct {
	issuer   string
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   oauth2.Config
}

func New(ctx context.Context, cfg Config) (*ProviderClient, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}
	scopes := append([]string(nil), cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "profile", "email"}
	}
	oauthCfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURL,
		Scopes:       scopes,
	}
	return &ProviderClient{
		issuer:   cfg.IssuerURL,
		provider: provider,
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
		oauth2:   oauthCfg,
	}, nil
}

func (c *ProviderClient) AuthCodeURL(state, nonce, codeVerifier string) string {
	challenge := codeChallengeS256(codeVerifier)
	return c.oauth2.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *ProviderClient) Exchange(ctx context.Context, code, nonce, codeVerifier string) (Identity, error) {
	token, err := c.oauth2.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange oidc code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("oidc token response missing id_token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, fmt.Errorf("verify id_token nonce: mismatch")
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("decode id_token claims: %w", err)
	}
	return Identity{
		Issuer:  idToken.Issuer,
		Subject: idToken.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
	}, nil
}

func (c *ProviderClient) Ping(ctx context.Context) error {
	_ = ctx
	if c.provider == nil || c.verifier == nil {
		return fmt.Errorf("oidc provider is not initialized")
	}
	return nil
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
