package vault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

var ErrNotFound = errors.New("credential not found")

type Credential struct {
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject"`
	Email             string    `json:"email"`
	N8NEmailOrLoginID string    `json:"n8n_email_or_login_id"`
	N8NPassword       string    `json:"n8n_password"`
	LinkedAt          time.Time `json:"linked_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Store interface {
	Get(ctx context.Context, issuer, subject string) (Credential, error)
	Put(ctx context.Context, cred Credential) error
	Delete(ctx context.Context, issuer, subject string) error
	Ping(ctx context.Context) error
}

type KVStore struct {
	client   *vaultapi.Client
	mount    string
	prefix   string
	roleID   string
	secretID string
}

type AuthConfig struct {
	Token    string
	RoleID   string
	SecretID string
}

func NewStore(ctx context.Context, addr string, auth AuthConfig, mount, prefix string) (*KVStore, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}
	store := &KVStore{
		client: client,
		mount:  strings.Trim(mount, "/"),
		prefix: strings.Trim(prefix, "/"),
	}
	if auth.Token != "" {
		client.SetToken(auth.Token)
	} else if auth.RoleID != "" && auth.SecretID != "" {
		ttl, err := loginAppRole(ctx, client, auth.RoleID, auth.SecretID)
		if err != nil {
			return nil, err
		}
		store.roleID = auth.RoleID
		store.secretID = auth.SecretID
		store.startTokenRenewal(ctx, ttl)
	} else {
		return nil, errors.New("vault auth is not configured")
	}
	return store, nil
}

func loginAppRole(ctx context.Context, client *vaultapi.Client, roleID, secretID string) (int, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return 0, fmt.Errorf("vault approle login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return 0, errors.New("vault approle login did not return a token")
	}
	client.SetToken(secret.Auth.ClientToken)
	return secret.Auth.LeaseDuration, nil
}

func (s *KVStore) startTokenRenewal(ctx context.Context, ttlSeconds int) {
	if ttlSeconds <= 0 {
		ttlSeconds = 3600
	}
	interval := time.Duration(ttlSeconds*2/3) * time.Second
	const minInterval = 5 * time.Minute
	if interval < minInterval {
		interval = minInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.client.Auth().Token().RenewSelfWithContext(ctx, 0); err != nil {
					slog.Warn("vault token renewal failed, attempting re-login", "error", err)
					if _, err2 := loginAppRole(ctx, s.client, s.roleID, s.secretID); err2 != nil {
						slog.Error("vault approle re-login failed", "error", err2)
					} else {
						slog.Info("vault approle re-login succeeded")
					}
				} else {
					slog.Debug("vault token renewed")
				}
			}
		}
	}()
}

func (s *KVStore) Get(ctx context.Context, issuer, subject string) (Credential, error) {
	secret, err := s.client.Logical().ReadWithContext(ctx, s.dataPath(issuer, subject))
	if err != nil {
		return Credential{}, fmt.Errorf("vault read credential: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return Credential{}, ErrNotFound
	}
	data, ok := secret.Data["data"].(map[string]any)
	if !ok || data == nil {
		return Credential{}, ErrNotFound
	}
	cred, err := decodeCredential(data)
	if err != nil {
		return Credential{}, err
	}
	return cred, nil
}

func (s *KVStore) Put(ctx context.Context, cred Credential) error {
	now := time.Now().UTC()
	if cred.LinkedAt.IsZero() {
		cred.LinkedAt = now
	}
	cred.UpdatedAt = now
	payload := map[string]any{
		"data": map[string]any{
			"issuer":                cred.Issuer,
			"subject":               cred.Subject,
			"email":                 cred.Email,
			"n8n_email_or_login_id": cred.N8NEmailOrLoginID,
			"n8n_password":          cred.N8NPassword,
			"linked_at":             cred.LinkedAt.Format(time.RFC3339),
			"updated_at":            cred.UpdatedAt.Format(time.RFC3339),
		},
	}
	if _, err := s.client.Logical().WriteWithContext(ctx, s.dataPath(cred.Issuer, cred.Subject), payload); err != nil {
		return fmt.Errorf("vault write credential: %w", err)
	}
	return nil
}

func (s *KVStore) Delete(ctx context.Context, issuer, subject string) error {
	if _, err := s.client.Logical().DeleteWithContext(ctx, s.metadataPath(issuer, subject)); err != nil {
		return fmt.Errorf("vault delete credential metadata: %w", err)
	}
	return nil
}

func (s *KVStore) Ping(ctx context.Context) error {
	_, err := s.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault token lookup: %w", err)
	}
	return nil
}

func (s *KVStore) dataPath(issuer, subject string) string {
	return path.Join(s.mount, "data", s.prefix, HashComponent(issuer), HashComponent(subject))
}

func (s *KVStore) metadataPath(issuer, subject string) string {
	return path.Join(s.mount, "metadata", s.prefix, HashComponent(issuer), HashComponent(subject))
}

func PathFor(prefix, issuer, subject string) string {
	return path.Join(strings.Trim(prefix, "/"), HashComponent(issuer), HashComponent(subject))
}

func HashComponent(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeCredential(data map[string]any) (Credential, error) {
	cred := Credential{
		Issuer:            stringValue(data["issuer"]),
		Subject:           stringValue(data["subject"]),
		Email:             stringValue(data["email"]),
		N8NEmailOrLoginID: stringValue(data["n8n_email_or_login_id"]),
		N8NPassword:       stringValue(data["n8n_password"]),
	}
	if cred.Issuer == "" || cred.Subject == "" || cred.N8NEmailOrLoginID == "" || cred.N8NPassword == "" {
		return Credential{}, errors.New("vault credential is missing required fields")
	}
	cred.LinkedAt = parseTime(stringValue(data["linked_at"]))
	cred.UpdatedAt = parseTime(stringValue(data["updated_at"]))
	return cred, nil
}

func stringValue(value any) string {
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
