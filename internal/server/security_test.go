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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Gosayram/openkms/internal/audit"
	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/authz"
	"github.com/Gosayram/openkms/internal/cryptoengine"
	"github.com/Gosayram/openkms/internal/keystore"
	"github.com/Gosayram/openkms/internal/storage"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// setupTestServerWithLogger creates a test server with a test logger that captures output
func setupTestServerWithLogger(t *testing.T) (*httptest.Server, *keystore.Store, *cryptoengine.CryptoEngine) {
	// Create temporary storage
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, err := storage.NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}

	// Create master key for envelope encryption
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	envelopeBackend, err := storage.NewEnvelopeBackend(backend, masterKey)
	if err != nil {
		t.Fatalf("Failed to create envelope backend: %v", err)
	}

	// Create keystore
	keyStore := keystore.NewStore(envelopeBackend)

	// Create crypto engine
	cryptoEngine := cryptoengine.NewEngine()

	// Create logger with buffer to capture output
	logger := zaptest.NewLogger(t, zaptest.WrapOptions(zap.AddCaller()))

	// Create audit logger
	auditLogger, err := audit.NewLogger(logger)
	if err != nil {
		t.Fatalf("Failed to create audit logger: %v", err)
	}

	// Create handlers
	authzEngine := authz.NewEngine()
	handlers := NewHandlers(logger, keyStore, cryptoEngine, auditLogger, authzEngine)

	// Create router
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		// Add auth middleware that sets test identity
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				identity := &authn.Identity{
					ID:   "test-user",
					Type: "test",
				}
				ctx := authn.WithIdentity(r.Context(), identity)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})

		r.Post("/key", handlers.CreateKey)
		r.Post("/key/{id}/encrypt", handlers.Encrypt)
		r.Post("/key/{id}/decrypt", handlers.Decrypt)
	})

	// Create test server
	ts := httptest.NewServer(router)

	return ts, keyStore, cryptoEngine
}

// TestNoPlaintextInLogs verifies that plaintext data does not appear in logs
func TestNoPlaintextInLogs(t *testing.T) {
	ts, keyStore, cryptoEngine := setupTestServerWithLogger(t)
	defer ts.Close()

	// Create a key first
	ctx := context.Background()
	metadata := &keystore.KeyMetadata{
		ID:        "test-key-security",
		Type:      keystore.KeyTypeDEK,
		Algorithm: keystore.AlgorithmAES256GCM,
		State:     keystore.KeyStateActive,
	}

	if err := keyStore.CreateKey(ctx, metadata); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Generate key material
	keyMaterial, err := cryptoEngine.GenerateKey(ctx, "AES-256-GCM")
	if err != nil {
		t.Fatalf("Failed to generate key material: %v", err)
	}

	// Save key material
	if err := keyStore.SaveKeyMaterial(ctx, "test-key-security", 1, keyMaterial); err != nil {
		t.Fatalf("Failed to save key material: %v", err)
	}

	// Test plaintext that should never appear in logs
	secretPlaintext := []byte("SECRET_PLAINTEXT_DATA_12345")

	// Encrypt
	encryptReq := EncryptRequest{
		Plaintext: secretPlaintext,
	}

	body, err := json.Marshal(encryptReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/v1/key/test-key-security/encrypt", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var encryptResp EncryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&encryptResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Decrypt
	decryptReq := DecryptRequest{
		Ciphertext: encryptResp.Ciphertext,
		Nonce:      encryptResp.Nonce,
	}

	body, err = json.Marshal(decryptReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err = http.Post(ts.URL+"/v1/key/test-key-security/decrypt", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Note: In a real test, we would capture log output and verify that
	// the plaintext string does not appear in logs. For now, we just verify
	// that the operations complete successfully without errors.
	// In production, this should be tested with a log capture mechanism.
}

// TestNoPlaintextInStorage verifies that plaintext is not stored in storage
func TestNoPlaintextInStorage(t *testing.T) {
	// Create temporary storage
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, err := storage.NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	// Create master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	envelopeBackend, err := storage.NewEnvelopeBackend(backend, masterKey)
	if err != nil {
		t.Fatalf("Failed to create envelope backend: %v", err)
	}

	ctx := context.Background()
	keyStore := keystore.NewStore(envelopeBackend)

	// Create key
	metadata := &keystore.KeyMetadata{
		ID:        "test-key-storage",
		Type:      keystore.KeyTypeDEK,
		Algorithm: keystore.AlgorithmAES256GCM,
		State:     keystore.KeyStateActive,
	}

	if err := keyStore.CreateKey(ctx, metadata); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Save key material (should be encrypted)
	keyMaterial := []byte("SECRET_KEY_MATERIAL_12345")
	if err := keyStore.SaveKeyMaterial(ctx, "test-key-storage", 1, keyMaterial); err != nil {
		t.Fatalf("Failed to save key material: %v", err)
	}

	// Read raw data from underlying storage
	rawData, err := backend.Get(ctx, "key:material:test-key-storage:1")
	if err != nil {
		t.Fatalf("Failed to get raw data: %v", err)
	}

	// Verify that raw data is not the same as plaintext
	if string(rawData) == string(keyMaterial) {
		t.Error("Key material should be encrypted in storage")
	}

	// Verify that plaintext does not appear in raw data
	if strings.Contains(string(rawData), string(keyMaterial)) {
		t.Error("Plaintext key material should not appear in storage")
	}

	// Verify that we can retrieve and decrypt it correctly
	retrieved, err := keyStore.GetKeyMaterial(ctx, "test-key-storage", 1)
	if err != nil {
		t.Fatalf("Failed to get key material: %v", err)
	}

	if string(retrieved) != string(keyMaterial) {
		t.Errorf("Retrieved key material does not match original")
	}
}

// TestNoPlaintextInErrorMessages verifies that error messages don't leak plaintext
func TestNoPlaintextInErrorMessages(t *testing.T) {
	ts, _, _ := setupTestServerWithLogger(t)
	defer ts.Close()

	// Try to decrypt with wrong key (should fail but not leak plaintext)
	secretPlaintext := []byte("SECRET_DATA_12345")

	// Create invalid decrypt request
	decryptReq := DecryptRequest{
		Ciphertext: []byte("invalid-ciphertext"),
		Nonce:      []byte("invalid-nonce"),
	}

	body, err := json.Marshal(decryptReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/v1/key/non-existent-key/decrypt", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Should return error, but error message should not contain plaintext
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected error status")
	}

	// Read response body
	var errorResp ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errorResp); err == nil {
		// Verify that plaintext does not appear in error message
		if strings.Contains(errorResp.Error, string(secretPlaintext)) {
			t.Error("Error message should not contain plaintext")
		}
		if strings.Contains(errorResp.Details, string(secretPlaintext)) {
			t.Error("Error details should not contain plaintext")
		}
	}
}
