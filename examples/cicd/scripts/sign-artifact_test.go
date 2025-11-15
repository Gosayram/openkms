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

//go:build integration
// +build integration

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/Gosayram/openkms/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignArtifactGo tests the Go utility for signing artifacts
func TestSignArtifactGo(t *testing.T) {
	// Skip test if environment variables are not set
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")
	keyID := os.Getenv("OPENKMS_KEY_ID")

	if url == "" || token == "" || keyID == "" {
		t.Skip("Skipping test: OPENKMS_URL, OPENKMS_TOKEN and OPENKMS_KEY_ID must be set")
	}

	// Create temporary file for testing
	testFile, err := os.CreateTemp("", "test-artifact-*.txt")
	require.NoError(t, err)
	defer os.Remove(testFile.Name())

	testContent := []byte("test artifact content for signing")
	_, err = testFile.Write(testContent)
	require.NoError(t, err)
	testFile.Close()

	// Create OpenKMS client
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: url,
		Token:   token,
	})
	require.NoError(t, err)

	// Sign file
	ctx := context.Background()
	signResp, err := client.Sign(ctx, keyID, testContent)
	require.NoError(t, err)
	require.NotEmpty(t, signResp.Signature)

	// Check signature format
	signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	require.NoError(t, err)
	assert.NotEmpty(t, signature)

	// Create Cosign-compatible format
	signatureJSON := createCosignSignature(signature, testContent)

	// Check that it's valid JSON
	var sigData map[string]interface{}
	err = json.Unmarshal(signatureJSON, &sigData)
	require.NoError(t, err)

	// Check required fields
	assert.Contains(t, sigData, "base64Signature")
	assert.NotEmpty(t, sigData["base64Signature"])

	// Save signature to temporary file
	sigFile := testFile.Name() + ".sig"
	err = os.WriteFile(sigFile, signatureJSON, 0o600)
	require.NoError(t, err)
	defer os.Remove(sigFile)

	// Check that signature file was created
	_, err = os.Stat(sigFile)
	assert.NoError(t, err)
}

// TestCosignSignatureFormat tests Cosign signature format
func TestCosignSignatureFormat(t *testing.T) {
	testPayload := []byte("test payload")
	testSignature := []byte("test signature")

	signatureJSON := createCosignSignature(testSignature, testPayload)

	// Check that it's valid JSON
	var sigData map[string]interface{}
	err := json.Unmarshal(signatureJSON, &sigData)
	require.NoError(t, err)

	// Check structure
	assert.Contains(t, sigData, "base64Signature")
	assert.Contains(t, sigData, "payload")

	// Check base64 encoding
	base64Sig, ok := sigData["base64Signature"].(string)
	require.True(t, ok)
	decodedSig, err := base64.StdEncoding.DecodeString(base64Sig)
	require.NoError(t, err)
	assert.Equal(t, testSignature, decodedSig)

	// Check payload
	payload, ok := sigData["payload"].([]byte)
	require.True(t, ok)
	assert.Equal(t, testPayload, payload)
}

// TestSignArtifactWithDifferentFiles tests signing different file types
func TestSignArtifactWithDifferentFiles(t *testing.T) {
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")
	keyID := os.Getenv("OPENKMS_KEY_ID")

	if url == "" || token == "" || keyID == "" {
		t.Skip("Skipping test: OPENKMS_URL, OPENKMS_TOKEN and OPENKMS_KEY_ID must be set")
	}

	client, err := sdk.NewClient(sdk.Config{
		BaseURL: url,
		Token:   token,
	})
	require.NoError(t, err)

	ctx := context.Background()

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
			name:    "large file",
			content: make([]byte, 1024*1024), // 1MB
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
		})
	}
}

// TestSignArtifactErrorHandling tests error handling
func TestSignArtifactErrorHandling(t *testing.T) {
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")

	if url == "" || token == "" {
		t.Skip("Skipping test: OPENKMS_URL and OPENKMS_TOKEN must be set")
	}

	// Test with invalid key
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: url,
		Token:   token,
	})
	require.NoError(t, err)

	ctx := context.Background()
	testContent := []byte("test content")

	// Try to sign with non-existent key
	_, err = client.Sign(ctx, "non-existent-key", testContent)
	assert.Error(t, err)

	// Test with invalid URL
	invalidClient, err := sdk.NewClient(sdk.Config{
		BaseURL: "https://invalid-url.example.com",
		Token:   token,
	})
	require.NoError(t, err)

	_, err = invalidClient.Sign(ctx, "test-key", testContent)
	assert.Error(t, err)
}

// BenchmarkSignArtifact benchmarks artifact signing
func BenchmarkSignArtifact(b *testing.B) {
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")
	keyID := os.Getenv("OPENKMS_KEY_ID")

	if url == "" || token == "" || keyID == "" {
		b.Skip("Skipping benchmark: OPENKMS_URL, OPENKMS_TOKEN and OPENKMS_KEY_ID must be set")
	}

	client, err := sdk.NewClient(sdk.Config{
		BaseURL: url,
		Token:   token,
	})
	require.NoError(b, err)

	testContent := []byte("benchmark test content")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.Sign(ctx, keyID, testContent)
		if err != nil {
			b.Fatal(err)
		}
	}
}
