package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yangs1202/n8n-gw/internal/security"
)

var ErrNotFound = errors.New("session value not found")

type Session struct {
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Linked    bool      `json:"linked"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OIDCState struct {
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	ReturnTo     string    `json:"return_to"`
	CreatedAt    time.Time `json:"created_at"`
}

type Store interface {
	CreateSession(ctx context.Context, sess Session) (string, error)
	SaveSession(ctx context.Context, id string, sess Session) error
	GetSession(ctx context.Context, id string) (Session, error)
	DeleteSession(ctx context.Context, id string) error
	StoreOIDCState(ctx context.Context, state string, value OIDCState) error
	TakeOIDCState(ctx context.Context, state string) (OIDCState, error)
	GetCSRF(ctx context.Context, sessionID string) (string, error)
	SetCSRF(ctx context.Context, sessionID, token string) error
	Ping(ctx context.Context) error
}

type RedisStore struct {
	client       *redis.Client
	sessionTTL   time.Duration
	oidcTTL      time.Duration
	csrfTokenTTL time.Duration
}

const (
	redisSessionPrefix   = "n8n_gw:session:"
	redisOIDCStatePrefix = "n8n_gw:oidc_state:"
	redisCSRFPrefix      = "n8n_gw:csrf:"
)

func NewRedisStore(redisURL string, sessionTTL, oidcTTL time.Duration) *RedisStore {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		opts = &redis.Options{Addr: redisURL}
	}
	return &RedisStore{
		client:       redis.NewClient(opts),
		sessionTTL:   sessionTTL,
		oidcTTL:      oidcTTL,
		csrfTokenTTL: sessionTTL,
	}
}

func (s *RedisStore) CreateSession(ctx context.Context, sess Session) (string, error) {
	id, err := security.RandomBase64URL(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	sess.CreatedAt = now
	sess.ExpiresAt = now.Add(s.sessionTTL)
	if err := s.SaveSession(ctx, id, sess); err != nil {
		return "", err
	}
	return id, nil
}

func (s *RedisStore) SaveSession(ctx context.Context, id string, sess Session) error {
	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := s.client.Set(ctx, redisSessionPrefix+id, payload, s.sessionTTL).Err(); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

func (s *RedisStore) GetSession(ctx context.Context, id string) (Session, error) {
	raw, err := s.client.Get(ctx, redisSessionPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("get session: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return Session{}, fmt.Errorf("unmarshal session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(ctx, id)
		return Session{}, ErrNotFound
	}
	return sess, nil
}

func (s *RedisStore) DeleteSession(ctx context.Context, id string) error {
	if err := s.client.Del(ctx, redisSessionPrefix+id, redisCSRFPrefix+id).Err(); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *RedisStore) StoreOIDCState(ctx context.Context, state string, value OIDCState) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal oidc state: %w", err)
	}
	if err := s.client.Set(ctx, redisOIDCStatePrefix+state, payload, s.oidcTTL).Err(); err != nil {
		return fmt.Errorf("store oidc state: %w", err)
	}
	return nil
}

func (s *RedisStore) TakeOIDCState(ctx context.Context, state string) (OIDCState, error) {
	key := redisOIDCStatePrefix + state
	raw, err := s.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return OIDCState{}, ErrNotFound
	}
	if err != nil {
		return OIDCState{}, fmt.Errorf("take oidc state: %w", err)
	}
	var value OIDCState
	if err := json.Unmarshal(raw, &value); err != nil {
		return OIDCState{}, fmt.Errorf("unmarshal oidc state: %w", err)
	}
	return value, nil
}

func (s *RedisStore) GetCSRF(ctx context.Context, sessionID string) (string, error) {
	token, err := s.client.Get(ctx, redisCSRFPrefix+sessionID).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get csrf: %w", err)
	}
	return token, nil
}

func (s *RedisStore) SetCSRF(ctx context.Context, sessionID, token string) error {
	if err := s.client.Set(ctx, redisCSRFPrefix+sessionID, token, s.csrfTokenTTL).Err(); err != nil {
		return fmt.Errorf("set csrf: %w", err)
	}
	return nil
}

func (s *RedisStore) Ping(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping: %w", err)
	}
	return nil
}
