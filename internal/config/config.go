package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var defaultBypassPrefixes = []string{
	"/webhook/",
	"/webhook-test/",
	"/webhook-waiting/",
	"/form/",
	"/form-test/",
	"/forms/",
	"/forms-test/",
}

type Config struct {
	ListenAddr               string
	PublicBaseURL            *url.URL
	N8NUpstreamURL           *url.URL
	OIDCIssuerURL            string
	OIDCClientID             string
	OIDCClientSecret         string
	OIDCScopes               []string
	RedisURL                 string
	VaultAddr                string
	VaultToken               string
	VaultRoleID              string
	VaultSecretID            string
	VaultKVMount             string
	VaultKVPrefix            string
	SessionTTL               time.Duration
	OIDCStateTTL             time.Duration
	ConsoleProxyTimeout      time.Duration
	PublicExecutionTimeout   time.Duration
	PublicExecutionBodyLimit int64
	PublicBypassPrefixes     []string
	CookieSecure             bool
	TrustedProxyCIDRs        []string
	LogLevel                 string
}

func Load() (Config, error) {
	var cfg Config
	var err error

	cfg.ListenAddr = envDefault("LISTEN_ADDR", ":8080")

	cfg.PublicBaseURL, err = parseRequiredURL("PUBLIC_BASE_URL")
	if err != nil {
		return Config{}, err
	}
	cfg.N8NUpstreamURL, err = parseRequiredURL("N8N_UPSTREAM_URL")
	if err != nil {
		return Config{}, err
	}

	cfg.OIDCIssuerURL = strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL"))
	cfg.OIDCClientID = strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID"))
	cfg.OIDCClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	cfg.RedisURL = strings.TrimSpace(os.Getenv("REDIS_URL"))
	cfg.VaultAddr = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	cfg.VaultToken = os.Getenv("VAULT_TOKEN")
	cfg.VaultRoleID = strings.TrimSpace(os.Getenv("VAULT_ROLE_ID"))
	cfg.VaultSecretID = os.Getenv("VAULT_SECRET_ID")

	if cfg.OIDCIssuerURL == "" || cfg.OIDCClientID == "" || cfg.OIDCClientSecret == "" || cfg.RedisURL == "" || cfg.VaultAddr == "" {
		return Config{}, errors.New("OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, REDIS_URL, and VAULT_ADDR are required")
	}
	if cfg.VaultToken == "" && (cfg.VaultRoleID == "" || cfg.VaultSecretID == "") {
		return Config{}, errors.New("either VAULT_TOKEN or both VAULT_ROLE_ID and VAULT_SECRET_ID are required")
	}

	cfg.OIDCScopes = fieldsDefault("OIDC_SCOPES", []string{"openid", "profile", "email"})
	cfg.VaultKVMount = envDefault("VAULT_KV_MOUNT", "secret")
	cfg.VaultKVPrefix = strings.Trim(strings.TrimSpace(envDefault("VAULT_KV_PREFIX", "n8n-gw/users")), "/")
	cfg.SessionTTL, err = durationDefault("SESSION_TTL", 8*time.Hour)
	if err != nil {
		return Config{}, err
	}
	cfg.OIDCStateTTL, err = durationDefault("OIDC_STATE_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}
	cfg.ConsoleProxyTimeout, err = durationDefault("CONSOLE_PROXY_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
	}
	cfg.PublicExecutionTimeout, err = durationDefault("PUBLIC_EXECUTION_TIMEOUT", 300*time.Second)
	if err != nil {
		return Config{}, err
	}
	cfg.PublicExecutionBodyLimit, err = int64Default("PUBLIC_EXECUTION_BODY_LIMIT", 50*1024*1024)
	if err != nil {
		return Config{}, err
	}
	cfg.PublicBypassPrefixes = csvDefault("PUBLIC_BYPASS_PREFIXES", defaultBypassPrefixes)
	cfg.CookieSecure = cfg.PublicBaseURL.Scheme == "https"
	if val := strings.TrimSpace(os.Getenv("COOKIE_SECURE")); val != "" {
		cfg.CookieSecure, err = strconv.ParseBool(val)
		if err != nil {
			return Config{}, fmt.Errorf("parse COOKIE_SECURE: %w", err)
		}
	}
	cfg.TrustedProxyCIDRs = csvDefault("TRUSTED_PROXY_CIDRS", nil)
	cfg.LogLevel = strings.ToLower(envDefault("LOG_LEVEL", "info"))

	return cfg, nil
}

func parseRequiredURL(key string) (*url.URL, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil, fmt.Errorf("%s is required", key)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%s must be an absolute URL", key)
	}
	return parsed, nil
}

func envDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func fieldsDefault(key string, fallback []string) []string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return strings.Fields(val)
	}
	return append([]string(nil), fallback...)
}

func csvDefault(key string, fallback []string) []string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return append([]string(nil), fallback...)
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func durationDefault(key string, fallback time.Duration) (time.Duration, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return duration, nil
}

func int64Default(key string, fallback int64) (int64, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return parsed, nil
}
