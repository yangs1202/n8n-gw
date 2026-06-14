package oidc

import (
	"context"
	"errors"
	"net/url"
)

type FakeClient struct {
	AuthURL      string
	Identity     Identity
	ExchangeFunc func(ctx context.Context, code, nonce, codeVerifier string) (Identity, error)
	PingFunc     func(ctx context.Context) error
}

func (c FakeClient) AuthCodeURL(state, nonce, codeVerifier string) string {
	_ = nonce
	_ = codeVerifier
	if c.AuthURL == "" {
		return "/fake-idp?state=" + url.QueryEscape(state)
	}
	return c.AuthURL + "?state=" + url.QueryEscape(state)
}

func (c FakeClient) Exchange(ctx context.Context, code, nonce, codeVerifier string) (Identity, error) {
	if c.ExchangeFunc != nil {
		return c.ExchangeFunc(ctx, code, nonce, codeVerifier)
	}
	if c.Identity.Subject == "" {
		return Identity{}, errors.New("fake oidc identity is empty")
	}
	return c.Identity, nil
}

func (c FakeClient) Ping(ctx context.Context) error {
	if c.PingFunc == nil {
		return nil
	}
	return c.PingFunc(ctx)
}
