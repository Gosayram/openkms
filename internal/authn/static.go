// Copyright 2025 Gosayram Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"
)

// StaticToken represents a static authentication token
type StaticToken struct {
	Token     string
	Identity  string
	ExpiresAt *time.Time
	Metadata  map[string]string
}

// StaticProvider implements static token authentication
type StaticProvider struct {
	tokens map[string]*StaticToken
	mu     sync.RWMutex
}

// NewStaticProvider creates a new static token provider
func NewStaticProvider() *StaticProvider {
	return &StaticProvider{
		tokens: make(map[string]*StaticToken),
	}
}

// AddToken adds a static token
func (s *StaticProvider) AddToken(token *StaticToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
}

// RemoveToken removes a static token
func (s *StaticProvider) RemoveToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// Authenticate authenticates using a static token
//
//nolint:revive // ctx parameter is required by Provider interface
func (s *StaticProvider) Authenticate(ctx context.Context, token string) (*Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use constant-time comparison to prevent timing attacks
	for storedToken, tokenData := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) == 1 {
			// Check expiration
			if tokenData.ExpiresAt != nil && time.Now().After(*tokenData.ExpiresAt) {
				return nil, fmt.Errorf("%w: token expired", ErrTokenExpired)
			}

			return &Identity{
				ID:       tokenData.Identity,
				Type:     "token",
				Metadata: tokenData.Metadata,
			}, nil
		}
	}

	return nil, ErrInvalidToken
}

// ValidateToken validates a static token
//
//nolint:revive // ctx parameter is required by Provider interface
func (s *StaticProvider) ValidateToken(ctx context.Context, token string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for storedToken, tokenData := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) == 1 {
			// Check expiration
			if tokenData.ExpiresAt != nil && time.Now().After(*tokenData.ExpiresAt) {
				return ErrTokenExpired
			}
			return nil
		}
	}

	return ErrInvalidToken
}

// LoadTokensFromConfig loads tokens from configuration
func (s *StaticProvider) LoadTokensFromConfig(tokens []StaticToken) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range tokens {
		s.tokens[token.Token] = &token
	}
}

// ListTokens returns all token identities (for admin use)
func (s *StaticProvider) ListTokens() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identities := make([]string, 0, len(s.tokens))
	for _, token := range s.tokens {
		identities = append(identities, token.Identity)
	}

	return identities
}
