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

// Package masterkey provides master key management policies including environment variable and file-based providers.
package masterkey

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
)

// EnvProvider retrieves master key from environment variable (dev only)
type EnvProvider struct {
	envVar string
}

// NewEnvProvider creates a new environment-based master key provider
func NewEnvProvider(envVar string) *EnvProvider {
	return &EnvProvider{
		envVar: envVar,
	}
}

// GetMasterKey retrieves the master key from environment variable
//
//nolint:revive // ctx parameter is required by Provider interface
func (e *EnvProvider) GetMasterKey(ctx context.Context) ([]byte, error) {
	keyHex := os.Getenv(e.envVar)
	if keyHex == "" {
		return nil, fmt.Errorf("environment variable %s is not set: %w", e.envVar, ErrMasterKeyNotFound)
	}

	// Decode hex string to bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode master key from hex: %w", err)
	}

	if len(key) != aes256MasterKeySize {
		return nil, fmt.Errorf(
			"invalid master key size: expected %d bytes, got %d: %w",
			aes256MasterKeySize,
			len(key),
			ErrInvalidMasterKey,
		)
	}

	return key, nil
}

// RotateMasterKey is not supported for env provider (dev only)
//
//nolint:revive // ctx parameter is required by Provider interface
func (e *EnvProvider) RotateMasterKey(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("master key rotation not supported for env provider")
}

// WrapKey encrypts a key using the master key
//
//nolint:revive // ctx parameter is required by Provider interface
func (e *EnvProvider) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	masterKey, err := e.GetMasterKey(ctx)
	if err != nil {
		return nil, err
	}
	// Use AES-GCM for wrapping
	return wrapKeyWithAESGCM(masterKey, key)
}

// UnwrapKey decrypts a key using the master key
//
//nolint:revive // ctx parameter is required by Provider interface
func (e *EnvProvider) UnwrapKey(ctx context.Context, wrappedKey []byte) ([]byte, error) {
	masterKey, err := e.GetMasterKey(ctx)
	if err != nil {
		return nil, err
	}
	// Use AES-GCM for unwrapping
	return unwrapKeyWithAESGCM(masterKey, wrappedKey)
}

// Close releases resources
func (e *EnvProvider) Close() error {
	return nil
}
