package n8n

import (
	"context"
	"errors"
	"net/http"
)

type FakeClient struct {
	LoginFunc       func(ctx context.Context, emailOrLoginID, password string) (LoginResult, error)
	CurrentUserFunc func(ctx context.Context, cookieHeader string) (CurrentUserResult, error)
	LogoutFunc      func(ctx context.Context, cookieHeader string) (LogoutResult, error)
	PingFunc        func(ctx context.Context) error
}

func (c FakeClient) Login(ctx context.Context, emailOrLoginID, password string, forwardedHeaders ...http.Header) (LoginResult, error) {
	if c.LoginFunc == nil {
		return LoginResult{}, errors.New("fake n8n LoginFunc is nil")
	}
	return c.LoginFunc(ctx, emailOrLoginID, password)
}

func (c FakeClient) CurrentUser(ctx context.Context, cookieHeader string) (CurrentUserResult, error) {
	if c.CurrentUserFunc == nil {
		return CurrentUserResult{StatusCode: 401, Body: []byte(`{"error":"unauthorized"}`), ContentType: "application/json"}, nil
	}
	return c.CurrentUserFunc(ctx, cookieHeader)
}

func (c FakeClient) Logout(ctx context.Context, cookieHeader string) (LogoutResult, error) {
	if c.LogoutFunc == nil {
		return LogoutResult{StatusCode: 200}, nil
	}
	return c.LogoutFunc(ctx, cookieHeader)
}

func (c FakeClient) Ping(ctx context.Context) error {
	if c.PingFunc == nil {
		return nil
	}
	return c.PingFunc(ctx)
}
