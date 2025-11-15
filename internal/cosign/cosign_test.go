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

package cosign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestNewSigner(t *testing.T) {
	// Generate Ed25519 key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	if signer == nil {
		t.Fatal("Signer is nil")
	}
}

func TestNewSigner_InvalidKeyType(t *testing.T) {
	// Try with invalid key type (RSA would be invalid, but we'll use nil)
	_, err := NewSigner(nil)
	if err == nil {
		t.Fatal("Expected error for invalid key type")
	}

	if err.Error() != "only Ed25519 keys are supported for Cosign signing" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestNewVerifier(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create verifier
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	if verifier == nil {
		t.Fatal("Verifier is nil")
	}
}

func TestNewVerifier_InvalidKeyType(t *testing.T) {
	// Try with invalid key type
	_, err := NewVerifier(nil)
	if err == nil {
		t.Fatal("Expected error for invalid key type")
	}

	if err.Error() != "only Ed25519 keys are supported for Cosign verification" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSignBlob_VerifyBlob(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer and verifier
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Test data
	testData := []byte("Hello, Cosign! This is a test blob for signing.")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	if len(signatureData) == 0 {
		t.Fatal("Signature data is empty")
	}

	// Verify the signature
	err = verifier.VerifyBlob(ctx, bytes.NewReader(testData), signatureData)
	if err != nil {
		t.Fatalf("Failed to verify blob: %v", err)
	}
}

func TestSignBlob_VerifyBlob_WrongData(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer and verifier
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Test data
	testData := []byte("Hello, Cosign!")
	modifiedData := []byte("Hello, Modified!")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Try to verify with wrong data - should fail
	err = verifier.VerifyBlob(ctx, bytes.NewReader(modifiedData), signatureData)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong data")
	}
}

func TestSignBlob_VerifyBlob_WrongKey(t *testing.T) {
	// Generate two different key pairs
	_, privateKey1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	publicKey2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer with key1 and verifier with key2
	signer, err := NewSigner(privateKey1)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	verifier, err := NewVerifier(publicKey2)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Test data
	testData := []byte("Hello, Cosign!")

	// Sign the blob with key1
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Try to verify with key2 - should fail
	err = verifier.VerifyBlob(ctx, bytes.NewReader(testData), signatureData)
	if err == nil {
		t.Fatal("Expected verification to fail with wrong key")
	}
}

func TestSignBlobFile_VerifyBlobFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cosign_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer and verifier
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Hello, Cosign! This is a test file.")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Sign the file
	ctx := context.Background()
	sigPath, err := signer.SignBlobFile(ctx, testFile)
	if err != nil {
		t.Fatalf("Failed to sign file: %v", err)
	}

	// Check signature file exists
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		t.Fatalf("Signature file was not created: %s", sigPath)
	}

	// Verify the signature
	err = verifier.VerifyBlobFile(ctx, testFile, sigPath)
	if err != nil {
		t.Fatalf("Failed to verify file: %v", err)
	}
}

func TestSignBlobFile_NonExistentFile(t *testing.T) {
	// Generate Ed25519 key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Try to sign non-existent file
	ctx := context.Background()
	_, err = signer.SignBlobFile(ctx, "/nonexistent/file.txt")
	if err == nil {
		t.Fatal("Expected error for non-existent file")
	}
}

func TestVerifyBlobFile_NonExistentFile(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create verifier
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Try to verify non-existent file
	ctx := context.Background()
	err = verifier.VerifyBlobFile(ctx, "/nonexistent/file.txt", "/nonexistent/file.txt.sig")
	if err == nil {
		t.Fatal("Expected error for non-existent file")
	}
}

func TestSignBlob_EmptyBlob(t *testing.T) {
	// Generate Ed25519 key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Sign empty blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("Failed to sign empty blob: %v", err)
	}

	if len(signatureData) == 0 {
		t.Fatal("Signature data is empty")
	}
}

func TestVerifyBlob_InvalidSignatureFormat(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create verifier
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Try to verify with invalid signature format
	ctx := context.Background()
	testData := []byte("test data")
	invalidSignature := []byte("not a valid JSON signature")

	err = verifier.VerifyBlob(ctx, bytes.NewReader(testData), invalidSignature)
	if err == nil {
		t.Fatal("Expected error for invalid signature format")
	}
}
