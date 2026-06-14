package session

import (
	"context"
	"sync"
	"time"

	"github.com/yangs1202/n8n-gw/internal/security"
)

type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	states   map[string]OIDCState
	csrf     map[string]string
	ttl      time.Duration
	stateTTL time.Duration
}

func NewMemoryStore(ttl, stateTTL time.Duration) *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]Session),
		states:   make(map[string]OIDCState),
		csrf:     make(map[string]string),
		ttl:      ttl,
		stateTTL: stateTTL,
	}
}

func (s *MemoryStore) CreateSession(ctx context.Context, sess Session) (string, error) {
	_ = ctx
	id, err := security.RandomBase64URL(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	sess.CreatedAt = now
	sess.ExpiresAt = now.Add(s.ttl)
	return id, s.SaveSession(context.Background(), id, sess)
}

func (s *MemoryStore) SaveSession(ctx context.Context, id string, sess Session) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = sess
	return nil
}

func (s *MemoryStore) GetSession(ctx context.Context, id string) (Session, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return Session{}, ErrNotFound
	}
	return sess, nil
}

func (s *MemoryStore) DeleteSession(ctx context.Context, id string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	delete(s.csrf, id)
	return nil
}

func (s *MemoryStore) StoreOIDCState(ctx context.Context, state string, value OIDCState) error {
	_ = ctx
	_ = s.stateTTL
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = value
	return nil
}

func (s *MemoryStore) TakeOIDCState(ctx context.Context, state string) (OIDCState, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.states[state]
	if !ok {
		return OIDCState{}, ErrNotFound
	}
	delete(s.states, state)
	return value, nil
}

func (s *MemoryStore) GetCSRF(ctx context.Context, sessionID string) (string, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.csrf[sessionID]
	if !ok {
		return "", ErrNotFound
	}
	return token, nil
}

func (s *MemoryStore) SetCSRF(ctx context.Context, sessionID, token string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrf[sessionID] = token
	return nil
}

func (s *MemoryStore) Ping(ctx context.Context) error {
	_ = ctx
	return nil
}
