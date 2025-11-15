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

package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/Gosayram/openkms/internal/policies/masterkey"
)

func TestEnvelopeBackend_Encryption(t *testing.T) {
	// Create master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	// Create temporary backend
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	baseBackend, err := NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer baseBackend.Close()

	// Wrap with envelope encryption
	envelopeBackend, err := NewEnvelopeBackend(baseBackend, masterKey)
	if err != nil {
		t.Fatalf("Failed to create envelope backend: %v", err)
	}

	ctx := context.Background()

	// Test Put/Get
	key := "test-key"
	value := []byte("sensitive data")

	if err := envelopeBackend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Verify data is encrypted in underlying storage
	rawData, err := baseBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get raw data: %v", err)
	}

	// Raw data should be different from plaintext
	if string(rawData) == string(value) {
		t.Error("Data should be encrypted in storage")
	}

	// Test Get (decryption)
	retrieved, err := envelopeBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("Expected %q, got %q", value, retrieved)
	}
}

func TestEnvelopeBackend_DifferentNonces(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	baseBackend, _ := NewBoltBackend(tmpFile.Name())
	defer baseBackend.Close()

	envelopeBackend, _ := NewEnvelopeBackend(baseBackend, masterKey)
	ctx := context.Background()

	key := "test-key"
	value := []byte("test value")

	// Put same value twice
	envelopeBackend.Put(ctx, key, value)
	raw1, _ := baseBackend.Get(ctx, key)

	envelopeBackend.Delete(ctx, key)
	envelopeBackend.Put(ctx, key, value)
	raw2, _ := baseBackend.Get(ctx, key)

	// Encrypted values should be different (different nonces)
	if string(raw1) == string(raw2) {
		t.Error("Encrypted values should be different due to different nonces")
	}

	// But both should decrypt to same value
	decrypted1, _ := envelopeBackend.Get(ctx, key)
	envelopeBackend.Delete(ctx, key)
	envelopeBackend.Put(ctx, key, value)
	decrypted2, _ := envelopeBackend.Get(ctx, key)

	if string(decrypted1) != string(value) || string(decrypted2) != string(value) {
		t.Error("Both encryptions should decrypt to same value")
	}
}

func TestEnvelopeBackend_WithProvider_DirectMode(t *testing.T) {
	// Create master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	// Set environment variable for EnvProvider
	keyHex := hex.EncodeToString(masterKey)
	os.Setenv("TEST_MASTER_KEY", keyHex)
	defer os.Unsetenv("TEST_MASTER_KEY")

	// Create provider
	provider := masterkey.NewEnvProvider("TEST_MASTER_KEY")

	// Create temporary backend
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	baseBackend, err := NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer baseBackend.Close()

	// Create envelope backend with provider (should use direct mode)
	envelopeBackend, err := NewEnvelopeBackendWithProvider(baseBackend, provider)
	if err != nil {
		t.Fatalf("Failed to create envelope backend: %v", err)
	}

	ctx := context.Background()

	// Test Put/Get
	key := "test-key"
	value := []byte("sensitive data")

	if err := envelopeBackend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Test Get (decryption)
	retrieved, err := envelopeBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("Expected %q, got %q", value, retrieved)
	}
}

func TestEnvelopeBackend_WithProvider_HSMMode(t *testing.T) {
	// Create a mock HSM provider that cannot extract master key
	// but supports wrap/unwrap
	mockProvider := &mockHSMProvider{}

	// Create temporary backend
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	baseBackend, err := NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer baseBackend.Close()

	// Create envelope backend with HSM provider (should use DEK mode)
	envelopeBackend, err := NewEnvelopeBackendWithProvider(baseBackend, mockProvider)
	if err != nil {
		t.Fatalf("Failed to create envelope backend: %v", err)
	}

	ctx := context.Background()

	// Test Put/Get
	key := "test-key"
	value := []byte("sensitive data")

	if err := envelopeBackend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Verify data format in storage (should have wrapped DEK)
	rawData, err := baseBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get raw data: %v", err)
	}

	// Should have format: [4 bytes: wrapped DEK length][wrapped DEK][nonce + ciphertext]
	if len(rawData) < 4 {
		t.Fatal("Encrypted data should have wrapped DEK length")
	}

	// Test Get (decryption)
	retrieved, err := envelopeBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("Expected %q, got %q", value, retrieved)
	}
}

// mockHSMProvider is a mock HSM provider for testing
type mockHSMProvider struct {
	masterKey []byte
}

func (m *mockHSMProvider) GetMasterKey(ctx context.Context) ([]byte, error) {
	// Simulate HSM: master key cannot be extracted
	return nil, fmt.Errorf("master key is stored in HSM and cannot be extracted")
}

func (m *mockHSMProvider) RotateMasterKey(ctx context.Context) ([]byte, error) {
	// Generate new master key
	m.masterKey = make([]byte, 32)
	rand.Read(m.masterKey)
	return nil, nil
}

func (m *mockHSMProvider) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	if m.masterKey == nil {
		// Initialize master key if not set
		m.masterKey = make([]byte, 32)
		rand.Read(m.masterKey)
	}
	// Use AES-GCM for wrapping (same as EnvProvider)
	return wrapKeyWithAESGCM(m.masterKey, key)
}

func (m *mockHSMProvider) UnwrapKey(ctx context.Context, wrappedKey []byte) ([]byte, error) {
	if m.masterKey == nil {
		return nil, fmt.Errorf("master key not initialized")
	}
	// Use AES-GCM for unwrapping (same as EnvProvider)
	return unwrapKeyWithAESGCM(m.masterKey, wrappedKey)
}

func (m *mockHSMProvider) Close() error {
	// Clear master key from memory
	if m.masterKey != nil {
		for i := range m.masterKey {
			m.masterKey[i] = 0
		}
		m.masterKey = nil
	}
	return nil
}

// wrapKeyWithAESGCM wraps a key using AES-GCM (helper function)
func wrapKeyWithAESGCM(masterKey, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce, key, nil)
	return ciphertext, nil
}

// unwrapKeyWithAESGCM unwraps a key using AES-GCM (helper function)
func unwrapKeyWithAESGCM(masterKey, wrappedKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(wrappedKey) < nonceSize {
		return nil, fmt.Errorf("wrapped key too short")
	}

	nonce, ciphertext := wrappedKey[:nonceSize], wrappedKey[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
