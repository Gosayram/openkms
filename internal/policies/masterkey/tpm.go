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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPMConfig contains configuration for TPM provider
type TPMConfig struct {
	TPMPath      string // Path to TPM device (e.g., /dev/tpm0 or /dev/tpmrm0)
	PCRSelection []int  // PCR selection for sealed storage (empty = no PCR binding)
	KeyLabel     string // Label for master key (for identification)
	UseSealed    bool   // Use sealed storage (true) or persistent key (false)
}

// TPMProvider implements master key provider using TPM 2.0
// Uses persistent key mode for master key protection
// Note: Sealed storage mode requires external storage for sealed data blob
type TPMProvider struct {
	rwc           io.ReadWriteCloser
	tpmPath       string
	pcrSelection  tpm2.PCRSelection
	keyLabel      string
	primaryHandle tpmutil.Handle // Primary key handle (SRK)
	keyHandle     tpmutil.Handle // Master key handle (persistent or session)
	mu            sync.Mutex     // Protects TPM operations
}

// NewTPMProvider creates a new TPM master key provider
func NewTPMProvider(config *TPMConfig) (*TPMProvider, error) {
	if config.TPMPath == "" {
		// Try default paths
		config.TPMPath = findTPMDevice()
		if config.TPMPath == "" {
			return nil, fmt.Errorf("TPM device not found (set tpm_path or ensure TPM is available)")
		}
	}

	// Open TPM device
	rwc, err := tpmutil.OpenTPM(config.TPMPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device %s: %w", config.TPMPath, err)
	}

	// Prepare PCR selection
	var pcrSelection tpm2.PCRSelection
	if len(config.PCRSelection) > 0 {
		pcrSelection = tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: config.PCRSelection,
		}
	}

	provider := &TPMProvider{
		rwc:          rwc,
		tpmPath:      config.TPMPath,
		pcrSelection: pcrSelection,
		keyLabel:     config.KeyLabel,
	}

	// Initialize primary key (SRK)
	// Note: For simplicity, we use primary key directly for encryption
	// In production, you might want to create a persistent child key
	if err := provider.initializePrimaryKey(); err != nil {
		_ = rwc.Close() // Best effort cleanup
		return nil, fmt.Errorf("failed to initialize primary key: %w", err)
	}

	return provider, nil
}

// findTPMDevice finds available TPM device
func findTPMDevice() string {
	paths := []string{
		"/dev/tpmrm0", // Kernel-managed resource manager (preferred)
		"/dev/tpm0",   // Direct TPM access
	}

	for _, path := range paths {
		// Try to open to check if device exists
		rwc, err := tpmutil.OpenTPM(path)
		if err == nil {
			_ = rwc.Close() // Best effort cleanup
			return path
		}
	}

	return ""
}

// initializePrimaryKey creates or retrieves the primary key (SRK)
func (p *TPMProvider) initializePrimaryKey() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Create primary key (SRK - Storage Root Key) using RSA template
	// Create RSA key with decrypt capability for encryption operations
	primaryHandle, _, err := tpm2.CreatePrimary(
		p.rwc,
		tpm2.HandleOwner,
		p.pcrSelection,
		"", "", // emptyAuth, emptySensitive
		tpm2.Public{
			Type:    tpm2.AlgRSA,
			NameAlg: tpm2.AlgSHA256,
			Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
				tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
				tpm2.FlagRestricted | tpm2.FlagDecrypt,
			RSAParameters: &tpm2.RSAParams{
				Symmetric: &tpm2.SymScheme{
					Alg:     tpm2.AlgAES,
					KeyBits: 128, //nolint:mnd // AES-128 for symmetric encryption
					Mode:    tpm2.AlgCFB,
				},
				KeyBits: 2048, //nolint:mnd // RSA-2048 key size
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create primary key: %w", err)
	}

	p.primaryHandle = primaryHandle

	// Use primary key directly for encryption/decryption
	// Note: Primary key is recreated each time (not persistent)
	// For production, consider using a persistent handle or child key
	// But TPM has limited key storage, so using primary key is simpler

	return nil
}

// GetMasterKey retrieves the master key
// For TPM, this returns an error because the key is not extractable
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *TPMProvider) GetMasterKey(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("master key is stored in TPM and cannot be extracted (use WrapKey/UnwrapKey instead)")
}

// RotateMasterKey generates a new master key in TPM
// For TPM, this recreates the primary key
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *TPMProvider) RotateMasterKey(ctx context.Context) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Flush old primary key if exists
	if p.primaryHandle != 0 {
		_ = tpm2.FlushContext(p.rwc, p.primaryHandle)
	}

	// Recreate primary key
	if err := p.initializePrimaryKey(); err != nil {
		return nil, fmt.Errorf("failed to rotate primary key: %w", err)
	}

	return nil, nil
}

// WrapKey encrypts a key using the master key in TPM
// Format: [4 bytes: encrypted DEK seed length][encrypted DEK seed][wrapped key with DEK]
// Uses TPM encryption for DEK seed, then AES-GCM for actual key wrapping
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *TPMProvider) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate DEK (Data Encryption Key)
	dek := make([]byte, aes256MasterKeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt entire DEK with TPM using primary key
	// TPM RSA encryption with OAEP: for RSA 2048, we can encrypt up to ~214 bytes
	// DEK is 32 bytes (AES-256), which fits comfortably
	oaepScheme := &tpm2.AsymScheme{
		Alg:  tpm2.AlgOAEP,
		Hash: tpm2.AlgSHA256,
	}
	encryptedDEK, err := tpm2.RSAEncrypt(
		p.rwc,
		p.primaryHandle,
		dek,
		oaepScheme,
		"", // label (empty)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with TPM: %w", err)
	}

	// Use the original DEK to wrap the key
	wrappedKey, err := wrapKeyWithAESGCM(dek, key)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key with DEK: %w", err)
	}

	// Combine: [4 bytes: encrypted DEK length][encrypted DEK][wrapped key]
	const lengthFieldSize = 4 //nolint:mnd // 4 bytes for uint32 length field
	encryptedDEKLen := make([]byte, lengthFieldSize)
	if len(encryptedDEK) > int(^uint32(0)) {
		return nil, fmt.Errorf("encrypted DEK too large: %d bytes", len(encryptedDEK))
	}
	//nolint:gosec // length is validated above, conversion is safe
	binary.BigEndian.PutUint32(encryptedDEKLen, uint32(len(encryptedDEK)))

	result := make([]byte, 0, lengthFieldSize+len(encryptedDEK)+len(wrappedKey))
	result = append(result, encryptedDEKLen...)
	result = append(result, encryptedDEK...)
	result = append(result, wrappedKey...)

	return result, nil
}

// UnwrapKey decrypts a key using the master key in TPM
// Format: [4 bytes: encrypted DEK length][encrypted DEK][wrapped key with DEK]
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *TPMProvider) UnwrapKey(ctx context.Context, wrappedKey []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Extract encrypted DEK length
	const lengthFieldSize = 4 //nolint:mnd // 4 bytes for uint32 length field
	if len(wrappedKey) < lengthFieldSize {
		return nil, fmt.Errorf("wrapped key too short: expected at least %d bytes, got %d", lengthFieldSize, len(wrappedKey))
	}

	encryptedDEKLen := binary.BigEndian.Uint32(wrappedKey[:lengthFieldSize])
	if encryptedDEKLen == 0 || len(wrappedKey) < int(lengthFieldSize+encryptedDEKLen) {
		return nil, fmt.Errorf("invalid wrapped key format: invalid encrypted DEK length")
	}

	// Extract encrypted DEK
	encryptedDEK := wrappedKey[lengthFieldSize : lengthFieldSize+encryptedDEKLen]

	// Decrypt entire DEK with TPM using RSA decryption with OAEP scheme
	oaepScheme := &tpm2.AsymScheme{
		Alg:  tpm2.AlgOAEP,
		Hash: tpm2.AlgSHA256,
	}
	dek, err := tpm2.RSADecrypt(
		p.rwc,
		p.primaryHandle,
		"", // emptyAuth
		encryptedDEK,
		oaepScheme,
		"", // label (empty)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with TPM: %w", err)
	}

	// Validate DEK size
	if len(dek) != aes256MasterKeySize {
		return nil, fmt.Errorf("invalid DEK size: expected %d bytes, got %d", aes256MasterKeySize, len(dek))
	}

	// Extract wrapped key
	wrappedKeyData := wrappedKey[lengthFieldSize+encryptedDEKLen:]

	// Unwrap the key with decrypted DEK
	key, err := unwrapKeyWithAESGCM(dek, wrappedKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key with DEK: %w", err)
	}

	return key, nil
}

// Close releases resources
func (p *TPMProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.rwc != nil {
		// Flush handles if needed
		if p.primaryHandle != 0 {
			_ = tpm2.FlushContext(p.rwc, p.primaryHandle)
		}
		if p.keyHandle != 0 {
			_ = tpm2.FlushContext(p.rwc, p.keyHandle)
		}

		err := p.rwc.Close()
		p.rwc = nil
		return err
	}

	return nil
}
