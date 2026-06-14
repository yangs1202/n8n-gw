package vault

import (
	"context"
	"sync"
)

type MemoryStore struct {
	mu    sync.Mutex
	items map[string]Credential
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: make(map[string]Credential)}
}

func (s *MemoryStore) Get(ctx context.Context, issuer, subject string) (Credential, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	cred, ok := s.items[PathFor("", issuer, subject)]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return cred, nil
}

func (s *MemoryStore) Put(ctx context.Context, cred Credential) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[PathFor("", cred.Issuer, cred.Subject)] = cred
	return nil
}

func (s *MemoryStore) Delete(ctx context.Context, issuer, subject string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, PathFor("", issuer, subject))
	return nil
}

func (s *MemoryStore) Ping(ctx context.Context) error {
	_ = ctx
	return nil
}
