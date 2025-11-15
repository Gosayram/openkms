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
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/cosign"
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

func TestArtifactSignature_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sig     *ArtifactSignature
		wantErr bool
	}{
		{
			name: "valid signature",
			sig: &ArtifactSignature{
				Base64Signature: "dGVzdA==", // base64("test")
			},
			wantErr: false,
		},
		{
			name: "empty signature",
			sig: &ArtifactSignature{
				Base64Signature: "",
			},
			wantErr: true,
		},
		{
			name: "invalid base64",
			sig: &ArtifactSignature{
				Base64Signature: "invalid base64!!!",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("ArtifactSignature.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestArtifactSignature_MarshalJSON(t *testing.T) {
	sig := &ArtifactSignature{
		Base64Signature: "dGVzdA==",
		Payload:         []byte("test payload"),
	}

	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Marshaled data is empty")
	}

	// Verify it can be unmarshaled back
	var unmarshaled ArtifactSignature
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if unmarshaled.Base64Signature != sig.Base64Signature {
		t.Errorf("Base64Signature mismatch: got %s, want %s", unmarshaled.Base64Signature, sig.Base64Signature)
	}

	if !bytes.Equal(unmarshaled.Payload, sig.Payload) {
		t.Errorf("Payload mismatch: got %v, want %v", unmarshaled.Payload, sig.Payload)
	}
}

func TestArtifactSignature_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name:    "standard format with payload",
			data:    `{"base64Signature":"dGVzdA==","payload":"dGVzdCBwYXlsb2Fk"}`,
			wantErr: false,
		},
		{
			name:    "standard format without payload",
			data:    `{"base64Signature":"dGVzdA=="}`,
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			data:    `{invalid json}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sig ArtifactSignature
			err := json.Unmarshal([]byte(tt.data), &sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("ArtifactSignature.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestArtifactSignature_ToLocalSignedPayload(t *testing.T) {
	sig := &ArtifactSignature{
		Base64Signature: "dGVzdA==",
		Payload:         []byte("test"),
	}

	lsp := sig.ToLocalSignedPayload()
	if lsp.Base64Signature != sig.Base64Signature {
		t.Errorf("Base64Signature mismatch: got %s, want %s", lsp.Base64Signature, sig.Base64Signature)
	}
}

func TestFromLocalSignedPayload(t *testing.T) {
	lsp := cosign.LocalSignedPayload{
		Base64Signature: "dGVzdA==",
	}
	payload := []byte("test payload")

	sig := FromLocalSignedPayload(lsp, payload)
	if sig.Base64Signature != lsp.Base64Signature {
		t.Errorf("Base64Signature mismatch: got %s, want %s", sig.Base64Signature, lsp.Base64Signature)
	}

	if !bytes.Equal(sig.Payload, payload) {
		t.Errorf("Payload mismatch: got %v, want %v", sig.Payload, payload)
	}
}

func TestParseArtifactSignature(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid signature",
			data:    []byte(`{"base64Signature":"dGVzdA==","payload":"dGVzdA=="}`),
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{invalid}`),
			wantErr: true,
		},
		{
			name:    "missing signature",
			data:    []byte(`{"payload":"dGVzdA=="}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := ParseArtifactSignature(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseArtifactSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && sig == nil {
				t.Error("ParseArtifactSignature() returned nil signature without error")
			}
		})
	}
}

func TestSignBlobStandard(t *testing.T) {
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
	testData := []byte("Hello, Cosign! Standard format test.")

	// Sign using standard format
	ctx := context.Background()
	signatureData, err := signer.SignBlobStandard(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	if len(signatureData) == 0 {
		t.Fatal("Signature data is empty")
	}

	// Verify the signature (standard format doesn't include payload, so we provide it)
	err = verifier.VerifyBlob(ctx, bytes.NewReader(testData), signatureData)
	if err != nil {
		t.Fatalf("Failed to verify blob: %v", err)
	}
}

func TestSignBlob_ArtifactSignatureFormat(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test data
	testData := []byte("Hello, Cosign! Artifact signature format test.")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Parse the signature to verify it's in ArtifactSignature format
	artifactSig, err := ParseArtifactSignature(signatureData)
	if err != nil {
		t.Fatalf("Failed to parse signature: %v", err)
	}

	// Verify signature structure
	if artifactSig.Base64Signature == "" {
		t.Fatal("Base64Signature is empty")
	}

	if len(artifactSig.Payload) == 0 {
		t.Fatal("Payload is empty in ArtifactSignature format")
	}

	if !bytes.Equal(artifactSig.Payload, testData) {
		t.Errorf("Payload mismatch: got %v, want %v", artifactSig.Payload, testData)
	}

	// Verify using verifier
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	err = verifier.VerifyBlob(ctx, bytes.NewReader(testData), signatureData)
	if err != nil {
		t.Fatalf("Failed to verify blob: %v", err)
	}
}

func TestVerifyBlob_StandardFormat(t *testing.T) {
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
	testData := []byte("Standard format verification test.")

	// Sign using standard format (without payload)
	ctx := context.Background()
	signatureData, err := signer.SignBlobStandard(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Verify - should work even without payload in signature
	err = verifier.VerifyBlob(ctx, bytes.NewReader(testData), signatureData)
	if err != nil {
		t.Fatalf("Failed to verify blob: %v", err)
	}
}

func TestVerifyBlob_PayloadMismatch(t *testing.T) {
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
	testData := []byte("Original data")
	modifiedData := []byte("Modified data")

	// Sign the blob (includes payload)
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Try to verify with different data - should fail
	err = verifier.VerifyBlob(ctx, bytes.NewReader(modifiedData), signatureData)
	if err == nil {
		t.Fatal("Expected verification to fail with payload mismatch")
	}
}

func TestExtractSignatureInfo(t *testing.T) {
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

	// Test data
	testData := []byte("Test data for signature info extraction")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Extract signature info
	info, err := ExtractSignatureInfo(signatureData)
	if err != nil {
		t.Fatalf("Failed to extract signature info: %v", err)
	}

	// Verify info
	if !info.HasPayload {
		t.Error("Expected signature to have payload")
	}

	if info.PayloadSize != len(testData) {
		t.Errorf("Payload size mismatch: got %d, want %d", info.PayloadSize, len(testData))
	}

	if info.SignatureSize != ed25519.SignatureSize {
		t.Errorf("Signature size mismatch: got %d, want %d", info.SignatureSize, ed25519.SignatureSize)
	}
}

func TestGetSignaturePayload(t *testing.T) {
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

	// Test data
	testData := []byte("Test payload extraction")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Extract payload
	payload, err := GetSignaturePayload(signatureData)
	if err != nil {
		t.Fatalf("Failed to get payload: %v", err)
	}

	if !bytes.Equal(payload, testData) {
		t.Errorf("Payload mismatch: got %v, want %v", payload, testData)
	}
}

func TestGetSignaturePayload_NoPayload(t *testing.T) {
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

	// Sign using standard format (without payload)
	ctx := context.Background()
	testData := []byte("Test data")
	signatureData, err := signer.SignBlobStandard(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Try to extract payload - should fail
	_, err = GetSignaturePayload(signatureData)
	if err == nil {
		t.Fatal("Expected error when payload is not present")
	}
}

func TestCheckSignatureFormat(t *testing.T) {
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

	// Test data
	testData := []byte("Test signature format check")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Check format - should succeed
	if err := CheckSignatureFormat(signatureData); err != nil {
		t.Fatalf("Failed to check signature format: %v", err)
	}

	// Check invalid format - should fail
	invalidData := []byte("invalid signature format")
	if err := CheckSignatureFormat(invalidData); err == nil {
		t.Fatal("Expected error for invalid signature format")
	}
}

func TestLoadPublicKeyFromFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cosign_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test raw key format
	keyFile := filepath.Join(tmpDir, "public.key")
	if err := os.WriteFile(keyFile, publicKey, 0o644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	loadedKey, err := LoadPublicKeyFromFile(keyFile)
	if err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}

	if !bytes.Equal(loadedKey.(ed25519.PublicKey), publicKey) {
		t.Error("Loaded key does not match original")
	}
}

func TestParsePublicKey(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "raw Ed25519 key",
			data:    publicKey,
			wantErr: false,
		},
		{
			name:    "base64 encoded key",
			data:    []byte(base64.StdEncoding.EncodeToString(publicKey)),
			wantErr: false,
		},
		{
			name:    "invalid key size",
			data:    []byte("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedKey, err := ParsePublicKey(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if parsedKey == nil {
					t.Error("ParsePublicKey() returned nil key without error")
				}
			}
		})
	}
}

func TestExtractPublicKeyFromPrivateKey(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Extract public key
	extractedKey, err := ExtractPublicKeyFromPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to extract public key: %v", err)
	}

	if !bytes.Equal(extractedKey.(ed25519.PublicKey), publicKey) {
		t.Error("Extracted key does not match original public key")
	}
}

func TestExtractPublicKeyFromPrivateKey_InvalidKey(t *testing.T) {
	// Try with invalid key type
	_, err := ExtractPublicKeyFromPrivateKey(nil)
	if err == nil {
		t.Fatal("Expected error for invalid key type")
	}
}

func TestValidatePublicKey(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Validate valid key
	if err := ValidatePublicKey(publicKey); err != nil {
		t.Fatalf("Failed to validate public key: %v", err)
	}

	// Validate invalid key
	if err := ValidatePublicKey(nil); err == nil {
		t.Fatal("Expected error for invalid key")
	}
}

func TestVerifySignatureBytes(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test data
	testData := []byte("Test signature bytes verification")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Verify signature bytes
	if err := VerifySignatureBytes(ctx, publicKey, testData, signatureData); err != nil {
		t.Fatalf("Failed to verify signature bytes: %v", err)
	}
}

func TestVerifyMultipleSignatures(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test data
	testData := []byte("Test multiple signatures verification")

	// Sign the blob multiple times
	ctx := context.Background()
	signature1, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	signature2, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Verify multiple signatures
	signatures := [][]byte{signature1, signature2}
	verified, errors := VerifyMultipleSignatures(ctx, publicKey, testData, signatures)
	if !verified {
		t.Fatalf("Failed to verify signatures: %v", errors)
	}

	if len(errors) > 0 {
		t.Errorf("Unexpected errors: %v", errors)
	}
}

func TestVerifyMultipleSignatures_AllInvalid(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test data
	testData := []byte("Test data")
	invalidSignatures := [][]byte{
		[]byte("invalid signature 1"),
		[]byte("invalid signature 2"),
	}

	// Verify multiple invalid signatures
	ctx := context.Background()
	verified, errors := VerifyMultipleSignatures(ctx, publicKey, testData, invalidSignatures)
	if verified {
		t.Fatal("Expected verification to fail")
	}

	if len(errors) == 0 {
		t.Fatal("Expected errors for invalid signatures")
	}
}

func TestFindSignatureFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cosign_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("test data")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create signature file
	sigFile := testFile + ".sig"
	sigData := []byte("signature data")
	if err := os.WriteFile(sigFile, sigData, 0o644); err != nil {
		t.Fatalf("Failed to write signature file: %v", err)
	}

	// Find signature file
	foundSigFile, err := FindSignatureFile(testFile)
	if err != nil {
		t.Fatalf("Failed to find signature file: %v", err)
	}

	if foundSigFile != sigFile {
		t.Errorf("Found signature file mismatch: got %s, want %s", foundSigFile, sigFile)
	}
}

func TestFindSignatureFile_NotFound(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cosign_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test file without signature
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("test data")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Try to find signature file - should fail
	_, err = FindSignatureFile(testFile)
	if err == nil {
		t.Fatal("Expected error when signature file not found")
	}
}

func TestReadSignatureFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cosign_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create signature file
	sigFile := filepath.Join(tmpDir, "test.sig")
	sigData := []byte("signature data")
	if err := os.WriteFile(sigFile, sigData, 0o644); err != nil {
		t.Fatalf("Failed to write signature file: %v", err)
	}

	// Read signature file
	readData, err := ReadSignatureFile(sigFile)
	if err != nil {
		t.Fatalf("Failed to read signature file: %v", err)
	}

	if !bytes.Equal(readData, sigData) {
		t.Errorf("Read data mismatch: got %v, want %v", readData, sigData)
	}
}

func TestWriteSignatureFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cosign_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write signature file
	sigFile := filepath.Join(tmpDir, "test.sig")
	sigData := []byte("signature data")
	if err := WriteSignatureFile(sigFile, sigData); err != nil {
		t.Fatalf("Failed to write signature file: %v", err)
	}

	// Verify file was created with correct permissions
	info, err := os.Stat(sigFile)
	if err != nil {
		t.Fatalf("Failed to stat signature file: %v", err)
	}

	if info.Mode().Perm() != signatureFilePerms {
		t.Errorf("File permissions mismatch: got %o, want %o", info.Mode().Perm(), signatureFilePerms)
	}

	// Read and verify content
	readData, err := os.ReadFile(sigFile)
	if err != nil {
		t.Fatalf("Failed to read signature file: %v", err)
	}

	if !bytes.Equal(readData, sigData) {
		t.Errorf("Read data mismatch: got %v, want %v", readData, sigData)
	}
}

func TestVerifySignatureFile(t *testing.T) {
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

	// Create signer
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	testData := []byte("Test signature file verification")
	if err := os.WriteFile(testFile, testData, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Sign the file
	ctx := context.Background()
	sigPath, err := signer.SignBlobFile(ctx, testFile)
	if err != nil {
		t.Fatalf("Failed to sign file: %v", err)
	}

	// Verify signature file with explicit path
	if err := VerifySignatureFile(ctx, publicKey, testFile, sigPath); err != nil {
		t.Fatalf("Failed to verify signature file: %v", err)
	}

	// Verify signature file with auto-find
	if err := VerifySignatureFile(ctx, publicKey, testFile, ""); err != nil {
		t.Fatalf("Failed to verify signature file with auto-find: %v", err)
	}
}

func TestCheckSignatureIntegrity(t *testing.T) {
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

	// Test data
	testData := []byte("Test signature integrity check")

	// Sign the blob
	ctx := context.Background()
	signatureData, err := signer.SignBlob(ctx, bytes.NewReader(testData))
	if err != nil {
		t.Fatalf("Failed to sign blob: %v", err)
	}

	// Check integrity - should succeed
	if err := CheckSignatureIntegrity(signatureData); err != nil {
		t.Fatalf("Failed to check signature integrity: %v", err)
	}

	// Check invalid signature - should fail
	invalidData := []byte("invalid signature")
	if err := CheckSignatureIntegrity(invalidData); err == nil {
		t.Fatal("Expected error for invalid signature")
	}
}
