package n8n

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidCredential = errors.New("invalid n8n credential")
	ErrMFARequired       = errors.New("n8n mfa required")
	ErrRateLimited       = errors.New("n8n login rate limited")
	ErrNoSessionCookie   = errors.New("n8n login did not return a session cookie")
)

type LoginResult struct {
	StatusCode int
	Body       []byte
	Cookies    []string
}

type CurrentUserResult struct {
	StatusCode  int
	Body        []byte
	Cookies     []string
	ContentType string
}

type LogoutResult struct {
	StatusCode int
	Cookies    []string
}

type Client interface {
	Login(ctx context.Context, emailOrLoginID, password string, forwardedHeaders ...http.Header) (LoginResult, error)
	CurrentUser(ctx context.Context, cookieHeader string) (CurrentUserResult, error)
	Logout(ctx context.Context, cookieHeader string) (LogoutResult, error)
	Ping(ctx context.Context) error
}

type HTTPClient struct {
	upstream *url.URL
	client   *http.Client
}

func NewClient(upstream *url.URL, timeout time.Duration) *HTTPClient {
	return &HTTPClient{
		upstream: upstream,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *HTTPClient) Login(ctx context.Context, emailOrLoginID, password string, forwardedHeaders ...http.Header) (LoginResult, error) {
	body, err := json.Marshal(map[string]string{
		"emailOrLdapLoginId": emailOrLoginID,
		"password":           password,
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("marshal n8n login body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.join("/rest/login"), bytes.NewReader(body))
	if err != nil {
		return LoginResult{}, fmt.Errorf("create n8n login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	copyLoginHeaders(req.Header, forwardedHeaders...)

	resp, err := c.client.Do(req)
	if err != nil {
		return LoginResult{}, fmt.Errorf("send n8n login request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	result := LoginResult{
		StatusCode: resp.StatusCode,
		Body:       respBody,
		Cookies:    resp.Header.Values("Set-Cookie"),
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return result, ErrRateLimited
	}
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		if looksLikeMFA(respBody) {
			return result, ErrMFARequired
		}
		return result, ErrInvalidCredential
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return result, fmt.Errorf("n8n login failed with status %d", resp.StatusCode)
	}
	if len(result.Cookies) == 0 {
		return result, ErrNoSessionCookie
	}
	return result, nil
}

func copyLoginHeaders(dst http.Header, sources ...http.Header) {
	for _, source := range sources {
		for _, name := range []string{
			"User-Agent",
			"Accept-Language",
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Forwarded-Proto",
			"X-Real-IP",
		} {
			if value := source.Get(name); value != "" {
				dst.Set(name, value)
			}
		}
	}
}

func (c *HTTPClient) CurrentUser(ctx context.Context, cookieHeader string) (CurrentUserResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.join("/rest/login"), nil)
	if err != nil {
		return CurrentUserResult{}, fmt.Errorf("create n8n current user request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return CurrentUserResult{}, fmt.Errorf("send n8n current user request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return CurrentUserResult{
		StatusCode:  resp.StatusCode,
		Body:        respBody,
		Cookies:     resp.Header.Values("Set-Cookie"),
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

func (c *HTTPClient) Logout(ctx context.Context, cookieHeader string) (LogoutResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.join("/rest/logout"), nil)
	if err != nil {
		return LogoutResult{}, fmt.Errorf("create n8n logout request: %w", err)
	}
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return LogoutResult{}, fmt.Errorf("send n8n logout request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	result := LogoutResult{StatusCode: resp.StatusCode, Cookies: resp.Header.Values("Set-Cookie")}
	if resp.StatusCode >= 500 {
		return result, fmt.Errorf("n8n logout failed with status %d", resp.StatusCode)
	}
	return result, nil
}

func (c *HTTPClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.join("/healthz"), nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		if resp.StatusCode < 500 {
			return nil
		}
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.join("/"), nil)
	if err != nil {
		return err
	}
	resp, err = c.client.Do(req)
	if err != nil {
		return fmt.Errorf("n8n ping: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 500 {
		return fmt.Errorf("n8n ping failed with status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) join(path string) string {
	next := *c.upstream
	next.Path = strings.TrimRight(c.upstream.Path, "/") + path
	next.RawQuery = ""
	return next.String()
}

func looksLikeMFA(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "mfa") || strings.Contains(lower, "998")
}
