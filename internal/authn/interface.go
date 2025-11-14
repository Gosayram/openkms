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
	"errors"
)

var (
	// ErrUnauthorized is returned when authentication fails
	ErrUnauthorized = errors.New("unauthorized")
	// ErrInvalidToken is returned when token is invalid
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired is returned when token has expired
	ErrTokenExpired = errors.New("token expired")
)

// Identity represents an authenticated identity
type Identity struct {
	ID       string
	Type     string // "token", "mtls", "oidc"
	Metadata map[string]string
}

// Provider defines the interface for authentication providers
type Provider interface {
	// Authenticate authenticates a request and returns identity
	Authenticate(ctx context.Context, token string) (*Identity, error)
	// ValidateToken validates a token without full authentication
	ValidateToken(ctx context.Context, token string) error
}

// Manager manages authentication providers
type Manager struct {
	providers []Provider
}

// NewManager creates a new authentication manager
func NewManager(providers ...Provider) *Manager {
	return &Manager{
		providers: providers,
	}
}

// Authenticate tries to authenticate using all providers
func (m *Manager) Authenticate(ctx context.Context, token string) (*Identity, error) {
	for _, provider := range m.providers {
		identity, err := provider.Authenticate(ctx, token)
		if err == nil {
			return identity, nil
		}
		// Continue to next provider on error
	}

	return nil, ErrUnauthorized
}

// ValidateToken validates token using all providers
func (m *Manager) ValidateToken(ctx context.Context, token string) error {
	for _, provider := range m.providers {
		if err := provider.ValidateToken(ctx, token); err == nil {
			return nil
		}
	}

	return ErrInvalidToken
}
