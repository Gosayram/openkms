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

package cicd_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Gosayram/openkms/pkg/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCICDIntegration tests full CI/CD examples integration
func TestCICDIntegration(t *testing.T) {
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")
	keyID := os.Getenv("OPENKMS_KEY_ID")

	if url == "" || token == "" || keyID == "" {
		t.Skip("Skipping test: OPENKMS_URL, OPENKMS_TOKEN and OPENKMS_KEY_ID must be set")
	}

	// Create test artifact
	testFile, err := os.CreateTemp("", "cicd-test-*.txt")
	require.NoError(t, err)
	defer os.Remove(testFile.Name())

	testContent := []byte("CI/CD integration test artifact")
	_, err = testFile.Write(testContent)
	require.NoError(t, err)
	testFile.Close()

	// Test 1: Signing via SDK
	t.Run("SDK signing", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: url,
			Token:   token,
		})
		require.NoError(t, err)

		ctx := context.Background()
		signResp, err := client.Sign(ctx, keyID, testContent)
		require.NoError(t, err)
		assert.NotEmpty(t, signResp.Signature)
	})

	// Test 2: Signature format check
	t.Run("Signature format", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: url,
			Token:   token,
		})
		require.NoError(t, err)

		ctx := context.Background()
		signResp, err := client.Sign(ctx, keyID, testContent)
		require.NoError(t, err)

		// Decode signature
		signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
		require.NoError(t, err)

		// Create Cosign format
		sigData := map[string]interface{}{
			"base64Signature": signResp.Signature,
			"payload":         testContent,
		}
		signatureJSON, err := json.Marshal(sigData)
		require.NoError(t, err)

		// Check JSON validity
		var parsed map[string]interface{}
		err = json.Unmarshal(signatureJSON, &parsed)
		require.NoError(t, err)
		assert.Contains(t, parsed, "base64Signature")
		assert.Contains(t, parsed, "payload")

		// Check that signature is not empty
		assert.NotEmpty(t, signature)
		assert.Greater(t, len(signature), 0)
	})

	// Test 3: Signature verification
	t.Run("Signature verification", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: url,
			Token:   token,
		})
		require.NoError(t, err)

		ctx := context.Background()

		// Sign
		signResp, err := client.Sign(ctx, keyID, testContent)
		require.NoError(t, err)

		// Verify
		verifyResp, err := client.Verify(ctx, keyID, testContent, []byte(signResp.Signature))
		require.NoError(t, err)
		assert.True(t, verifyResp.Valid)
	})

	// Test 4: Public key export
	t.Run("Public key export", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: url,
			Token:   token,
		})
		require.NoError(t, err)

		ctx := context.Background()
		keyResp, err := client.GetKey(ctx, keyID)
		require.NoError(t, err)
		assert.NotEmpty(t, keyResp.ID)
		assert.Equal(t, keyID, keyResp.ID)
	})
}

// TestScriptIntegration tests integration with sign-artifact.sh script
func TestScriptIntegration(t *testing.T) {
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")
	keyID := os.Getenv("OPENKMS_KEY_ID")

	if url == "" || token == "" || keyID == "" {
		t.Skip("Skipping test: OPENKMS_URL, OPENKMS_TOKEN and OPENKMS_KEY_ID must be set")
	}

	// Check if script exists
	scriptPath := filepath.Join("scripts", "sign-artifact.sh")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Skip("Script sign-artifact.sh not found")
	}

	// Create test file
	testFile, err := os.CreateTemp("", "script-test-*.txt")
	require.NoError(t, err)
	defer os.Remove(testFile.Name())

	testContent := []byte("Script integration test")
	_, err = testFile.Write(testContent)
	require.NoError(t, err)
	testFile.Close()

	// Create output file
	sigFile := testFile.Name() + ".sig"
	defer os.Remove(sigFile)

	// Run script
	cmd := exec.Command("bash", scriptPath,
		"--key-id", keyID,
		"--file", testFile.Name(),
		"--url", url,
		"--token", token,
		"--output", sigFile,
	)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Script output: %s", string(output))
		// Don't fail if script is not found or cannot be executed
		if _, ok := err.(*exec.Error); ok {
			t.Skip("Script cannot be executed (bash or openkms-cli may be missing)")
		}
		require.NoError(t, err)
	}

	// Check that signature file was created
	_, err = os.Stat(sigFile)
	if err != nil {
		t.Logf("Signature file not created, script may require openkms-cli in PATH")
		t.Skip("Script failed to create signature file")
	}

	// Check signature file contents
	sigData, err := os.ReadFile(sigFile)
	require.NoError(t, err)

	// Check that it's valid JSON
	var parsed map[string]interface{}
	err = json.Unmarshal(sigData, &parsed)
	require.NoError(t, err)
	assert.Contains(t, parsed, "base64Signature")
}

// TestMultipleArtifacts tests signing multiple artifacts
func TestMultipleArtifacts(t *testing.T) {
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

			// Verify each signature
			verifyResp, err := client.Verify(ctx, keyID, artifact.content, []byte(signResp.Signature))
			require.NoError(t, err)
			assert.True(t, verifyResp.Valid)
		})
	}

	// Check that all signatures are unique (for different content)
	assert.NotEqual(t, signatures["binary1"], signatures["binary2"])
	assert.NotEqual(t, signatures["binary2"], signatures["binary3"])
}

// TestErrorScenarios tests various error scenarios
func TestErrorScenarios(t *testing.T) {
	url := os.Getenv("OPENKMS_URL")
	token := os.Getenv("OPENKMS_TOKEN")

	if url == "" || token == "" {
		t.Skip("Skipping test: OPENKMS_URL and OPENKMS_TOKEN must be set")
	}

	t.Run("Invalid key ID", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: url,
			Token:   token,
		})
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.Sign(ctx, "invalid-key-id", []byte("test"))
		assert.Error(t, err)
	})

	t.Run("Invalid token", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: url,
			Token:   "invalid-token",
		})
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.Sign(ctx, "test-key", []byte("test"))
		assert.Error(t, err)
	})

	t.Run("Invalid URL", func(t *testing.T) {
		client, err := sdk.NewClient(sdk.Config{
			BaseURL: "https://invalid-url.example.com",
			Token:   token,
		})
		require.NoError(t, err)

		ctx := context.Background()
		_, err = client.Sign(ctx, "test-key", []byte("test"))
		assert.Error(t, err)
	})
}
