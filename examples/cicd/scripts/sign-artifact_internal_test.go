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

//go:build !integration
// +build !integration

// This file uses build tags (!integration) to avoid conflicts with sign-artifact_test.go (which uses integration tag).
// The linter may show "redeclared" errors, but these are false positives - the build tags ensure
// only one file is compiled at a time. Tests work correctly with: go test (runs this file) or go test -tags=integration (runs sign-artifact_test.go).
//
//nolint:dupl,typecheck // Build tags prevent actual conflicts, linter doesn't understand build tags
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gosayram/openkms/internal/audit"
	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/authz"
	"github.com/Gosayram/openkms/internal/cryptoengine"
	"github.com/Gosayram/openkms/internal/keystore"
	"github.com/Gosayram/openkms/internal/server"
	"github.com/Gosayram/openkms/internal/storage"
	"github.com/Gosayram/openkms/pkg/sdk"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupInternalTestServer creates a test server with all dependencies
//
//nolint:dupl // This function is intentionally similar to other test setup functions
func setupInternalTestServer(t *testing.T) (*httptest.Server, *keystore.Store) {
	// Create temporary storage
	tmpFile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, err := storage.NewBoltBackend(tmpFile.Name())
	require.NoError(t, err)

	// Create master key for envelope encryption
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	envelopeBackend, err := storage.NewEnvelopeBackend(backend, masterKey)
	require.NoError(t, err)

	// Create keystore
	keyStore := keystore.NewStore(envelopeBackend)

	// Create crypto engine
	cryptoEngine := cryptoengine.NewEngine()

	// Create logger
	logger := zap.NewNop()

	// Create audit logger
	auditLogger, err := audit.NewLogger(logger)
	require.NoError(t, err)

	// Create handlers
	authzEngine := authz.NewEngine()
	handlers := server.NewHandlers(logger, keyStore, cryptoEngine, auditLogger, authzEngine)

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
		r.Post("/key/{id}/sign", handlers.Sign)
		r.Post("/key/{id}/verify", handlers.Verify)
	})

	// Create test server
	ts := httptest.NewServer(router)

	return ts, keyStore
}

// TestSignArtifactInternalWithTestServer tests the Go utility with an in-memory test server
func TestSignArtifactInternalWithTestServer(t *testing.T) {
	// Setup test server
	ts, _ := setupInternalTestServer(t)
	defer ts.Close()

	// Create a signing key via HTTP API
	keyID := "test-signing-key"
	createKeyReq := map[string]string{
		"id":        keyID,
		"type":      "signing-key",
		"algorithm": "Ed25519",
	}
	reqBody, err := json.Marshal(createKeyReq)
	require.NoError(t, err)

	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	ctx := context.Background()

	// Create temporary file for testing
	testFile, err := os.CreateTemp("", "test-artifact-*.txt")
	require.NoError(t, err)
	defer os.Remove(testFile.Name())

	testContent := []byte("test artifact content for signing")
	_, err = testFile.Write(testContent)
	require.NoError(t, err)
	testFile.Close()

	// Create OpenKMS client pointing to test server
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: ts.URL,
		Token:   "test-token", // Not used in test server
	})
	require.NoError(t, err)

	// Sign file
	signResp, err := client.Sign(ctx, keyID, testContent)
	require.NoError(t, err)
	require.NotEmpty(t, signResp.Signature)

	// Check signature format - SDK returns base64 string
	signatureBytes, err := base64.StdEncoding.DecodeString(signResp.Signature)
	require.NoError(t, err)
	assert.NotEmpty(t, signatureBytes)

	// Create Cosign-compatible format
	signatureJSON := createCosignSignature(signatureBytes, testContent)

	// Check that it's valid JSON
	var sigData map[string]interface{}
	err = json.Unmarshal(signatureJSON, &sigData)
	require.NoError(t, err)

	// Check required fields
	assert.Contains(t, sigData, "base64Signature")
	assert.NotEmpty(t, sigData["base64Signature"])

	// Verify signature - SDK expects bytes, it will encode to base64 internally
	// Note: SDK's Verify method encodes both data and signature to base64 before sending
	verifyResp, err := client.Verify(ctx, keyID, testContent, signatureBytes)
	if err != nil {
		t.Logf("Verify error: %v", err)
		t.Logf("Signature (base64): %s", signResp.Signature)
		t.Logf("Signature (bytes length): %d", len(signatureBytes))
	}
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid, "Signature verification failed")
}

// TestSignArtifactGoUtilityInternalWithTestServer tests the full Go utility workflow
func TestSignArtifactGoUtilityInternalWithTestServer(t *testing.T) {
	// Setup test server
	ts, _ := setupInternalTestServer(t)
	defer ts.Close()

	// Create a signing key via HTTP API
	keyID := "test-signing-key"
	createKeyReq := map[string]string{
		"id":        keyID,
		"type":      "signing-key",
		"algorithm": "Ed25519",
	}
	reqBody, err := json.Marshal(createKeyReq)
	require.NoError(t, err)

	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	ctx := context.Background()

	// Create temporary file for testing
	testFile, err := os.CreateTemp("", "test-artifact-*.txt")
	require.NoError(t, err)
	defer os.Remove(testFile.Name())

	testContent := []byte("test artifact content for signing")
	_, err = testFile.Write(testContent)
	require.NoError(t, err)
	testFile.Close()

	// Set environment variables for the utility
	oldURL := os.Getenv("OPENKMS_URL")
	oldToken := os.Getenv("OPENKMS_TOKEN")
	oldKeyID := os.Getenv("OPENKMS_KEY_ID")

	defer func() {
		if oldURL != "" {
			os.Setenv("OPENKMS_URL", oldURL)
		} else {
			os.Unsetenv("OPENKMS_URL")
		}
		if oldToken != "" {
			os.Setenv("OPENKMS_TOKEN", oldToken)
		} else {
			os.Unsetenv("OPENKMS_TOKEN")
		}
		if oldKeyID != "" {
			os.Setenv("OPENKMS_KEY_ID", oldKeyID)
		} else {
			os.Unsetenv("OPENKMS_KEY_ID")
		}
	}()

	os.Setenv("OPENKMS_URL", ts.URL)
	os.Setenv("OPENKMS_TOKEN", "test-token")
	os.Setenv("OPENKMS_KEY_ID", keyID)

	// Create output file
	sigFile := testFile.Name() + ".sig"
	defer os.Remove(sigFile)

	// Simulate what the main function does
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: ts.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	// Read file
	fileData, err := os.ReadFile(testFile.Name())
	require.NoError(t, err)

	// Sign file
	signResp, err := client.Sign(ctx, keyID, fileData)
	require.NoError(t, err)

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	require.NoError(t, err)

	// Create Cosign-compatible signature format
	signatureJSON := createCosignSignature(signature, fileData)

	// Write signature to file
	err = os.WriteFile(sigFile, signatureJSON, 0o600)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(sigFile)
	assert.NoError(t, err)

	// Verify signature file contents
	sigData, err := os.ReadFile(sigFile)
	require.NoError(t, err)

	// Check that it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(sigData, &parsed)
	require.NoError(t, err)
	assert.Contains(t, parsed, "base64Signature")
	assert.Contains(t, parsed, "payload")
}

// TestCosignSignatureFormatInternalWithTestServer tests Cosign signature format with test server
func TestCosignSignatureFormatInternalWithTestServer(t *testing.T) {
	// Setup test server
	ts, _ := setupInternalTestServer(t)
	defer ts.Close()

	// Create a signing key via HTTP API
	keyID := "test-signing-key"
	createKeyReq := map[string]string{
		"id":        keyID,
		"type":      "signing-key",
		"algorithm": "Ed25519",
	}
	reqBody, err := json.Marshal(createKeyReq)
	require.NoError(t, err)

	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	ctx := context.Background()

	// Create OpenKMS client
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: ts.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	testCases := []struct {
		name    string
		content []byte
	}{
		{
			name:    "text file",
			content: []byte("Hello, World!"),
		},
		{
			name:    "binary file",
			content: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
		},
		{
			name:    "empty file",
			content: []byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signResp, err := client.Sign(ctx, keyID, tc.content)
			require.NoError(t, err)
			require.NotEmpty(t, signResp.Signature)

			// Check that signature is valid
			signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)

			// Create Cosign format
			signatureJSON := createCosignSignature(signature, tc.content)

			// Check JSON validity
			var sigData map[string]interface{}
			err = json.Unmarshal(signatureJSON, &sigData)
			require.NoError(t, err)
			assert.Contains(t, sigData, "base64Signature")

			// Verify signature - decode base64 signature first
			signatureBytes, err := base64.StdEncoding.DecodeString(signResp.Signature)
			require.NoError(t, err)
			verifyResp, err := client.Verify(ctx, keyID, tc.content, signatureBytes)
			require.NoError(t, err)
			assert.True(t, verifyResp.Valid)
		})
	}
}

// TestSignArtifactErrorHandlingInternalWithTestServer tests error handling with test server
func TestSignArtifactErrorHandlingInternalWithTestServer(t *testing.T) {
	// Setup test server
	ts, _ := setupInternalTestServer(t)
	defer ts.Close()

	ctx := context.Background()
	testContent := []byte("test content")

	// Test with invalid key
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: ts.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	_, err = client.Sign(ctx, "non-existent-key", testContent)
	assert.Error(t, err)
}

// TestSignArtifactMultipleFilesInternalWithTestServer tests signing multiple files
func TestSignArtifactMultipleFilesInternalWithTestServer(t *testing.T) {
	// Setup test server
	ts, _ := setupInternalTestServer(t)
	defer ts.Close()

	// Create a signing key via HTTP API
	keyID := "test-signing-key"
	createKeyReq := map[string]string{
		"id":        keyID,
		"type":      "signing-key",
		"algorithm": "Ed25519",
	}
	reqBody, err := json.Marshal(createKeyReq)
	require.NoError(t, err)

	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	ctx := context.Background()

	// Create OpenKMS client
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: ts.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	// Create multiple test files
	artifacts := []struct {
		name    string
		content []byte
	}{
		{"binary1", []byte("binary artifact 1")},
		{"binary2", []byte("binary artifact 2")},
		{"binary3", []byte("binary artifact 3")},
	}

	signatures := make(map[string]string)

	for _, artifact := range artifacts {
		t.Run(artifact.name, func(t *testing.T) {
			signResp, err := client.Sign(ctx, keyID, artifact.content)
			require.NoError(t, err)
			assert.NotEmpty(t, signResp.Signature)

			signatures[artifact.name] = signResp.Signature

			// Verify each signature - decode base64 signature first
			signatureBytes, err := base64.StdEncoding.DecodeString(signResp.Signature)
			require.NoError(t, err)
			verifyResp, err := client.Verify(ctx, keyID, artifact.content, signatureBytes)
			require.NoError(t, err)
			assert.True(t, verifyResp.Valid)
		})
	}

	// Check that all signatures are unique (for different content)
	assert.NotEqual(t, signatures["binary1"], signatures["binary2"])
	assert.NotEqual(t, signatures["binary2"], signatures["binary3"])
}

// TestSignArtifactFileOperationsInternalWithTestServer tests file operations
func TestSignArtifactFileOperationsInternalWithTestServer(t *testing.T) {
	// Setup test server
	ts, _ := setupInternalTestServer(t)
	defer ts.Close()

	// Create a signing key via HTTP API
	keyID := "test-signing-key"
	createKeyReq := map[string]string{
		"id":        keyID,
		"type":      "signing-key",
		"algorithm": "Ed25519",
	}
	reqBody, err := json.Marshal(createKeyReq)
	require.NoError(t, err)

	resp, err := http.Post(ts.URL+"/v1/key", "application/json", bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	ctx := context.Background()

	// Create temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "test-sign-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("test content")
	err = os.WriteFile(testFile, testContent, 0o644)
	require.NoError(t, err)

	// Create OpenKMS client
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: ts.URL,
		Token:   "test-token",
	})
	require.NoError(t, err)

	// Sign file
	signResp, err := client.Sign(ctx, keyID, testContent)
	require.NoError(t, err)

	// Create signature file
	sigFile := testFile + ".sig"
	signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	require.NoError(t, err)
	signatureJSON := createCosignSignature(signature, testContent)
	err = os.WriteFile(sigFile, signatureJSON, 0o600)
	require.NoError(t, err)

	// Verify signature file exists and has correct permissions
	info, err := os.Stat(sigFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// Verify signature file contents
	sigData, err := os.ReadFile(sigFile)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(sigData, &parsed)
	require.NoError(t, err)
	assert.Contains(t, parsed, "base64Signature")
}
