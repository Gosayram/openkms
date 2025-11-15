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

package masterkey

import (
	"context"
	"errors"
)

var (
	// ErrMasterKeyNotFound is returned when master key is not found
	ErrMasterKeyNotFound = errors.New("master key not found")
	// ErrInvalidMasterKey is returned when master key is invalid
	ErrInvalidMasterKey = errors.New("invalid master key")
)

// Provider defines the interface for master key providers
type Provider interface {
	// GetMasterKey retrieves the master key
	// For HSM providers, this may return an error if the key is not extractable
	GetMasterKey(ctx context.Context) ([]byte, error)
	// RotateMasterKey rotates the master key (returns new key)
	RotateMasterKey(ctx context.Context) ([]byte, error)
	// WrapKey encrypts a key using the master key
	// This is used for envelope encryption where the master key is in HSM
	WrapKey(ctx context.Context, key []byte) ([]byte, error)
	// UnwrapKey decrypts a key using the master key
	// This is used for envelope decryption where the master key is in HSM
	UnwrapKey(ctx context.Context, wrappedKey []byte) ([]byte, error)
	// Close releases resources
	Close() error
}

// Manager manages master key operations
type Manager struct {
	provider Provider
}

// NewManager creates a new master key manager
func NewManager(provider Provider) *Manager {
	return &Manager{
		provider: provider,
	}
}

// GetMasterKey retrieves the master key
func (m *Manager) GetMasterKey(ctx context.Context) ([]byte, error) {
	key, err := m.provider.GetMasterKey(ctx)
	if err != nil {
		return nil, err
	}

	// Validate key size (must be 32 bytes for AES-256)
	if len(key) != aes256MasterKeySize {
		return nil, ErrInvalidMasterKey
	}

	return key, nil
}

// RotateMasterKey rotates the master key
func (m *Manager) RotateMasterKey(ctx context.Context) ([]byte, error) {
	return m.provider.RotateMasterKey(ctx)
}

// Close closes the manager
func (m *Manager) Close() error {
	return m.provider.Close()
}

// GetProvider returns the underlying provider
func (m *Manager) GetProvider() Provider {
	return m.provider
}
