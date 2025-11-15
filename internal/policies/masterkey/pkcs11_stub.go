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

//go:build !cgo

package masterkey

import (
	"context"
	"fmt"
)

// PKCS11Config contains configuration for PKCS#11 provider
type PKCS11Config struct {
	LibraryPath string // Path to PKCS#11 library (e.g., /usr/lib/softhsm/libsofthsm2.so)
	SlotID      uint   // Slot ID (0 = auto-detect)
	TokenLabel  string // Token label (optional, for finding token by label)
	PIN         string // PIN for token authentication
	KeyLabel    string // Label for master key in HSM
	KeyID       string // ID for master key in HSM (optional)
}

// PKCS11Provider implements master key provider using PKCS#11 (HSM)
// This is a stub implementation that returns errors when CGO is disabled
type PKCS11Provider struct {
	keyLabel string // Key label (for error messages)
}

// NewPKCS11Provider creates a new PKCS#11 master key provider
// Returns an error when CGO is disabled, as PKCS#11 requires CGO
func NewPKCS11Provider(config *PKCS11Config) (*PKCS11Provider, error) {
	return nil, fmt.Errorf("PKCS#11 provider requires CGO to be enabled (CGO_ENABLED=1). This binary was built without CGO support")
}

// GetMasterKey retrieves the master key
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *PKCS11Provider) GetMasterKey(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("PKCS#11 provider requires CGO to be enabled")
}

// RotateMasterKey generates a new master key in HSM
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *PKCS11Provider) RotateMasterKey(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("PKCS#11 provider requires CGO to be enabled")
}

// WrapKey encrypts a key using the master key in HSM
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *PKCS11Provider) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("PKCS#11 provider requires CGO to be enabled")
}

// UnwrapKey decrypts a key using the master key in HSM
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *PKCS11Provider) UnwrapKey(ctx context.Context, wrappedKey []byte) ([]byte, error) {
	return nil, fmt.Errorf("PKCS#11 provider requires CGO to be enabled")
}

// Close releases resources
func (p *PKCS11Provider) Close() error {
	return nil
}
