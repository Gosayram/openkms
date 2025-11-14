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
	"testing"

	"github.com/Gosayram/openkms/internal/audit"
	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/authz"
	"github.com/Gosayram/openkms/internal/cryptoengine"
	"github.com/Gosayram/openkms/internal/keystore"
	"github.com/Gosayram/openkms/internal/storage"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// setupTestServer creates a test server with all dependencies
func setupTestServer(t *testing.T) (*httptest.Server, *keystore.Store, *cryptoengine.CryptoEngine) {
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

	// Create logger
	logger := zap.NewNop()

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
		r.Get("/key/{id}", handlers.GetKey)
		r.Post("/key/{id}/encrypt", handlers.Encrypt)
		r.Post("/key/{id}/decrypt", handlers.Decrypt)
		r.Post("/key/{id}/sign", handlers.Sign)
		r.Post("/key/{id}/verify", handlers.Verify)
		r.Post("/key/{id}/hmac", handlers.HMAC)
		r.Post("/random", handlers.GetRandom)
	})

	// Create test server
	ts := httptest.NewServer(router)

	return ts, keyStore, cryptoEngine
}

func TestCreateKey(t *testing.T) {
	ts, _, _ := setupTestServer(t)
	defer ts.Close()

	reqBody := CreateKeyRequest{
		ID:        "test-key-1",
		Type:      "dek",
		Algorithm: "AES-256-GCM",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	var createResp CreateKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if createResp.ID != reqBody.ID {
		t.Errorf("Expected ID %q, got %q", reqBody.ID, createResp.ID)
	}
}

func TestGetKey(t *testing.T) {
	ts, keyStore, _ := setupTestServer(t)
	defer ts.Close()

	// First create a key
	ctx := context.Background()
	metadata := &keystore.KeyMetadata{
		ID:        "test-key-2",
		Type:      keystore.KeyTypeDEK,
		Algorithm: keystore.AlgorithmAES256GCM,
		State:     keystore.KeyStateActive,
	}

	if err := keyStore.CreateKey(ctx, metadata); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Now get it
	resp, err := http.Get(ts.URL + "/v1/key/test-key-2")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var getResp GetKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&getResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if getResp.ID != "test-key-2" {
		t.Errorf("Expected ID %q, got %q", "test-key-2", getResp.ID)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	ts, keyStore, cryptoEngine := setupTestServer(t)
	defer ts.Close()

	// Create a key first
	ctx := context.Background()
	metadata := &keystore.KeyMetadata{
		ID:        "test-key-3",
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
	if err := keyStore.SaveKeyMaterial(ctx, "test-key-3", 1, keyMaterial); err != nil {
		t.Fatalf("Failed to save key material: %v", err)
	}

	// Encrypt
	plaintext := []byte("test plaintext data")
	encryptReq := EncryptRequest{
		Plaintext: plaintext,
	}

	body, err := json.Marshal(encryptReq)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/v1/key/test-key-3/encrypt", "application/json", bytes.NewBuffer(body))
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

	if len(encryptResp.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	if len(encryptResp.Nonce) == 0 {
		t.Error("Nonce is empty")
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

	resp, err = http.Post(ts.URL+"/v1/key/test-key-3/decrypt", "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var decryptResp DecryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&decryptResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if string(decryptResp.Plaintext) != string(plaintext) {
		t.Errorf("Expected plaintext %q, got %q", string(plaintext), string(decryptResp.Plaintext))
	}
}

func TestGetRandom(t *testing.T) {
	ts, _, _ := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/random?bytes=32", "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var randomResp GetRandomResponse
	if err := json.NewDecoder(resp.Body).Decode(&randomResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if randomResp.Bytes != 32 {
		t.Errorf("Expected 32 bytes, got %d", randomResp.Bytes)
	}

	if len(randomResp.Random) == 0 {
		t.Error("Random bytes are empty")
	}
}

func TestGetKeyNotFound(t *testing.T) {
	ts, _, _ := setupTestServer(t)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/key/non-existent-key")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}
