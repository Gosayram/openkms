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

// Package cosign provides Cosign-compatible artifact signing and verification.
// Supports Cosign v3+ only.
package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/oci"
	"github.com/sigstore/cosign/v3/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	// signatureFilePerms is the file permissions for signature files (read/write for owner only)
	signatureFilePerms = 0o600
)

// ArtifactSignature represents a Cosign-compatible artifact signature format.
// This structure supports both standard LocalSignedPayload format and extended format with payload.
type ArtifactSignature struct {
	// Base64Signature is the base64-encoded signature of the artifact
	Base64Signature string `json:"base64Signature"`
	// Payload is the optional artifact payload (blob data) included for verification convenience
	Payload []byte `json:"payload,omitempty"`
	// Bundle is an optional Sigstore bundle for transparency log integration
	// Using interface{} to match Cosign's LocalSignedPayload which uses bundle.RekorBundle
	Bundle interface{} `json:"bundle,omitempty"`
}

// ToLocalSignedPayload converts ArtifactSignature to Cosign LocalSignedPayload format
func (a *ArtifactSignature) ToLocalSignedPayload() cosign.LocalSignedPayload {
	lsp := cosign.LocalSignedPayload{
		Base64Signature: a.Base64Signature,
	}
	// Bundle will be set if it's a valid RekorBundle type
	// We skip it here as it requires specific type from cosign/bundle package
	return lsp
}

// FromLocalSignedPayload creates ArtifactSignature from Cosign LocalSignedPayload
func FromLocalSignedPayload(lsp cosign.LocalSignedPayload, payload []byte) *ArtifactSignature {
	return &ArtifactSignature{
		Base64Signature: lsp.Base64Signature,
		Payload:         payload,
		Bundle:          lsp.Bundle,
	}
}

// MarshalJSON marshals ArtifactSignature to JSON
func (a *ArtifactSignature) MarshalJSON() ([]byte, error) {
	// Use standard JSON marshaling but ensure proper field names
	type alias ArtifactSignature
	return json.Marshal((*alias)(a))
}

// UnmarshalJSON unmarshals JSON to ArtifactSignature
func (a *ArtifactSignature) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as LocalSignedPayload (standard Cosign format)
	var lsp cosign.LocalSignedPayload
	if err := json.Unmarshal(data, &lsp); err == nil && lsp.Base64Signature != "" {
		// Try to extract payload if present in extended format
		var extended struct {
			cosign.LocalSignedPayload
			Payload []byte `json:"payload,omitempty"`
		}
		if err := json.Unmarshal(data, &extended); err == nil {
			a.Base64Signature = extended.Base64Signature
			a.Payload = extended.Payload
			a.Bundle = extended.Bundle
			return nil
		}
		// Standard format without payload
		a.Base64Signature = lsp.Base64Signature
		a.Bundle = lsp.Bundle
		return nil
	}

	// Fallback to direct unmarshaling
	type alias ArtifactSignature
	return json.Unmarshal(data, (*alias)(a))
}

// Validate validates the ArtifactSignature structure
func (a *ArtifactSignature) Validate() error {
	if a.Base64Signature == "" {
		return fmt.Errorf("base64Signature is required")
	}

	// Validate base64 encoding
	if _, err := base64.StdEncoding.DecodeString(a.Base64Signature); err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}

	return nil
}

// Signer provides Cosign-compatible signing functionality
type Signer struct {
	signer signature.Signer
}

// NewSigner creates a new Cosign signer from a private key
func NewSigner(privateKey crypto.PrivateKey) (*Signer, error) {
	edKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("only Ed25519 keys are supported for Cosign signing")
	}

	// Create a signer from the private key
	signer, err := signature.LoadSigner(edKey, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &Signer{
		signer: signer,
	}, nil
}

// SignBlob signs a blob (file) and returns the signature in Cosign format
// Returns a JSON-encoded ArtifactSignature compatible with Cosign v3
func (s *Signer) SignBlob(ctx context.Context, blob io.Reader) ([]byte, error) {
	// Read the blob
	blobData, err := io.ReadAll(blob)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}

	// Sign the blob using Cosign v3 API
	sig, err := s.signer.SignMessage(bytes.NewReader(blobData), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to sign blob: %w", err)
	}

	// Create artifact signature with payload included for verification convenience
	artifactSig := &ArtifactSignature{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
		Payload:         blobData,
	}

	// Marshal to JSON
	payloadJSON, err := json.Marshal(artifactSig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return payloadJSON, nil
}

// SignBlobStandard signs a blob and returns signature in standard Cosign LocalSignedPayload format
// without including the payload (payload must be provided separately during verification)
func (s *Signer) SignBlobStandard(ctx context.Context, blob io.Reader) ([]byte, error) {
	// Read the blob
	blobData, err := io.ReadAll(blob)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob: %w", err)
	}

	// Sign the blob using Cosign v3 API
	sig, err := s.signer.SignMessage(bytes.NewReader(blobData), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to sign blob: %w", err)
	}

	// Create standard LocalSignedPayload format (without payload)
	payload := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
	}

	// Marshal to JSON
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return payloadJSON, nil
}

// SignBlobFile signs a file and writes the signature to a file
func (s *Signer) SignBlobFile(ctx context.Context, filePath string) (string, error) {
	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)

	// Open the file
	file, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Sign the blob
	signatureData, err := s.SignBlob(ctx, file)
	if err != nil {
		return "", err
	}

	// Write signature to file with secure permissions
	sigPath := cleanPath + ".sig"
	if err := os.WriteFile(sigPath, signatureData, signatureFilePerms); err != nil {
		return "", fmt.Errorf("failed to write signature file: %w", err)
	}

	return sigPath, nil
}

// SignContainer signs a container image reference using Cosign v3 API
// Note: This is a simplified implementation. For production use, consider using
// the full Cosign CLI or implementing the complete signing flow with payload generation.
func (s *Signer) SignContainer(ctx context.Context, imageRef string) error {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %w", err)
	}

	// Get the signed entity
	remoteOpts := []ociremote.Option{}
	se, err := ociremote.SignedEntity(ref, remoteOpts...)
	if err != nil {
		return fmt.Errorf("failed to get signed entity: %w", err)
	}

	// Get the image digest
	var digest v1.Hash
	if si, ok := se.(oci.SignedImage); ok {
		digest, err = si.Digest()
		if err != nil {
			return fmt.Errorf("failed to get image digest: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported signed entity type for signing")
	}

	// Create the payload for signing using internal payload package approach
	// We use a simple JSON payload with the image reference and digest
	payload := map[string]interface{}{
		"critical": map[string]interface{}{
			"identity": map[string]string{
				"docker-reference": ref.String(),
			},
			"image": map[string]string{
				"docker-manifest-digest": digest.String(),
			},
			"type": "cosign container image signature",
		},
	}

	// Marshal payload
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Sign the payload
	sig, err := s.signer.SignMessage(bytes.NewReader(payloadJSON), signatureoptions.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create OCI signature
	ociSig, err := static.NewSignature(payloadJSON, base64.StdEncoding.EncodeToString(sig))
	if err != nil {
		return fmt.Errorf("failed to create OCI signature: %w", err)
	}

	// Attach signature to the entity using mutate package
	newSE, err := mutate.AttachSignatureToEntity(se, ociSig)
	if err != nil {
		return fmt.Errorf("failed to attach signature: %w", err)
	}

	// Write the signed entity back to the registry
	if err := ociremote.WriteSignatures(ref.Context(), newSE, remoteOpts...); err != nil {
		return fmt.Errorf("failed to write signatures: %w", err)
	}

	return nil
}

// Verifier provides Cosign-compatible verification functionality
type Verifier struct {
	publicKey crypto.PublicKey
}

// NewVerifier creates a new Cosign verifier from a public key
func NewVerifier(publicKey crypto.PublicKey) (*Verifier, error) {
	_, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only Ed25519 keys are supported for Cosign verification")
	}

	return &Verifier{
		publicKey: publicKey,
	}, nil
}

// VerifyBlob verifies a Cosign signature for a blob
// Supports both ArtifactSignature format and standard LocalSignedPayload format
func (v *Verifier) VerifyBlob(ctx context.Context, blob io.Reader, signatureData []byte) error {
	// Parse signature using ArtifactSignature (supports both formats)
	var artifactSig ArtifactSignature
	if err := json.Unmarshal(signatureData, &artifactSig); err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	// Validate signature structure
	if err := artifactSig.Validate(); err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// Read the blob
	blobData, err := io.ReadAll(blob)
	if err != nil {
		return fmt.Errorf("failed to read blob: %w", err)
	}

	// If payload is included in signature, verify it matches the blob
	if len(artifactSig.Payload) > 0 {
		if !bytes.Equal(artifactSig.Payload, blobData) {
			return fmt.Errorf("payload in signature does not match provided blob")
		}
	}

	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(artifactSig.Base64Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create verifier
	verifier, err := signature.LoadVerifier(v.publicKey, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Verify signature against blob data
	if err := verifier.VerifySignature(
		bytes.NewReader(sig),
		bytes.NewReader(blobData),
		signatureoptions.WithContext(ctx),
	); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// ParseArtifactSignature parses signature data into ArtifactSignature structure
func ParseArtifactSignature(signatureData []byte) (*ArtifactSignature, error) {
	var artifactSig ArtifactSignature
	if err := json.Unmarshal(signatureData, &artifactSig); err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	if err := artifactSig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	return &artifactSig, nil
}

// VerifyBlobFile verifies a signature file for a blob file
func (v *Verifier) VerifyBlobFile(ctx context.Context, filePath, sigPath string) error {
	// Clean the file paths to prevent directory traversal
	cleanFilePath := filepath.Clean(filePath)
	cleanSigPath := filepath.Clean(sigPath)

	// Read the file
	file, err := os.Open(cleanFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Read the signature
	sigData, err := os.ReadFile(cleanSigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	return v.VerifyBlob(ctx, file, sigData)
}

// VerifyContainer verifies a container image signature using Cosign v3 API
func (v *Verifier) VerifyContainer(ctx context.Context, imageRef string) error {
	// Parse the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("failed to parse image reference: %w", err)
	}

	// Create verifier
	verifier, err := signature.LoadVerifier(v.publicKey, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Get the signed entity
	remoteOpts := []ociremote.Option{}
	se, err := ociremote.SignedEntity(ref, remoteOpts...)
	if err != nil {
		return fmt.Errorf("failed to get signed entity: %w", err)
	}

	// Get signatures
	sigs, err := se.Signatures()
	if err != nil {
		return fmt.Errorf("failed to get signatures: %w", err)
	}

	// Get image digest
	var imgDigest v1.Hash
	if si, ok := se.(oci.SignedImage); ok {
		imgDigest, err = si.Digest()
		if err != nil {
			return fmt.Errorf("failed to get image digest: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported signed entity type")
	}

	// Verify signatures using Cosign v3 API
	checkOpts := &cosign.CheckOpts{
		RootCerts:   nil, // We're using direct key verification
		SigVerifier: verifier,
	}

	// Get all signatures
	sigList, err := sigs.Get()
	if err != nil {
		return fmt.Errorf("failed to get signatures: %w", err)
	}

	// Verify each signature
	verified := false
	var lastErr error
	for _, sig := range sigList {
		bundleVerified, err := cosign.VerifyImageSignature(ctx, sig, imgDigest, checkOpts)
		if err != nil {
			lastErr = err
			continue
		}
		if bundleVerified {
			verified = true
			break
		}
	}

	if !verified {
		if lastErr != nil {
			return fmt.Errorf("signature verification failed: %w", lastErr)
		}
		return fmt.Errorf("no valid signatures found")
	}

	return nil
}

// SignatureInfo contains information about a signature
type SignatureInfo struct {
	// HasPayload indicates if the signature includes payload
	HasPayload bool
	// PayloadSize is the size of payload in bytes (0 if not present)
	PayloadSize int
	// SignatureSize is the size of the decoded signature in bytes
	SignatureSize int
	// HasBundle indicates if the signature includes a bundle
	HasBundle bool
}

// ExtractSignatureInfo extracts information from a signature
func ExtractSignatureInfo(signatureData []byte) (*SignatureInfo, error) {
	artifactSig, err := ParseArtifactSignature(signatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(artifactSig.Base64Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	info := &SignatureInfo{
		HasPayload:    len(artifactSig.Payload) > 0,
		PayloadSize:   len(artifactSig.Payload),
		SignatureSize: len(sigBytes),
		HasBundle:     artifactSig.Bundle != nil,
	}

	return info, nil
}

// GetSignaturePayload extracts payload from signature if present
func GetSignaturePayload(signatureData []byte) ([]byte, error) {
	artifactSig, err := ParseArtifactSignature(signatureData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	if len(artifactSig.Payload) == 0 {
		return nil, fmt.Errorf("signature does not contain payload")
	}

	return artifactSig.Payload, nil
}

// CheckSignatureFormat checks if signature data is in valid format
func CheckSignatureFormat(signatureData []byte) error {
	_, err := ParseArtifactSignature(signatureData)
	return err
}

// LoadPublicKeyFromFile loads a public key from a file
// Supports PEM format and raw Ed25519 public key (32 bytes)
func LoadPublicKeyFromFile(filePath string) (crypto.PublicKey, error) {
	cleanPath := filepath.Clean(filePath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return ParsePublicKey(data)
}

// ParsePublicKey parses a public key from bytes
// Supports PEM format and raw Ed25519 public key (32 bytes)
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		// Try to parse as PKIX public key
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			edKey, ok := pub.(ed25519.PublicKey)
			if !ok {
				return nil, fmt.Errorf("public key is not Ed25519")
			}
			return edKey, nil
		}

		// Try to parse as raw Ed25519 public key
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
	}

	// Try raw Ed25519 public key (32 bytes)
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}

	// Try base64 encoded Ed25519 public key
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}

	return nil, fmt.Errorf("unable to parse public key: unsupported format")
}

// ExtractPublicKeyFromPrivateKey extracts public key from a private key
func ExtractPublicKeyFromPrivateKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	edKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	return edKey.Public(), nil
}

// ValidatePublicKey validates that a public key is a valid Ed25519 key
func ValidatePublicKey(publicKey crypto.PublicKey) error {
	_, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not Ed25519")
	}
	return nil
}

// VerifySignatureBytes verifies a signature from bytes without reading from file
func VerifySignatureBytes(ctx context.Context, publicKey crypto.PublicKey, blobData, signatureData []byte) error {
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	return verifier.VerifyBlob(ctx, bytes.NewReader(blobData), signatureData)
}

// VerifyMultipleSignatures verifies multiple signatures against the same blob
// Returns true if at least one signature is valid
func VerifyMultipleSignatures(
	ctx context.Context,
	publicKey crypto.PublicKey,
	blobData []byte,
	signatures [][]byte,
) (bool, []error) {
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		return false, []error{fmt.Errorf("failed to create verifier: %w", err)}
	}

	var errors []error
	for i, sig := range signatures {
		err := verifier.VerifyBlob(ctx, bytes.NewReader(blobData), sig)
		if err == nil {
			return true, nil
		}
		errors = append(errors, fmt.Errorf("signature %d: %w", i, err))
	}

	return false, errors
}

// FindSignatureFile finds a signature file for a given file path
// Checks common patterns: file.sig, file.signature, .sig extension
func FindSignatureFile(filePath string) (string, error) {
	cleanPath := filepath.Clean(filePath)

	// Try common signature file patterns
	patterns := []string{
		cleanPath + ".sig",
		cleanPath + ".signature",
		strings.TrimSuffix(cleanPath, filepath.Ext(cleanPath)) + ".sig",
	}

	for _, pattern := range patterns {
		if _, err := os.Stat(pattern); err == nil {
			return pattern, nil
		}
	}

	return "", fmt.Errorf("signature file not found for %s", filePath)
}

// ReadSignatureFile reads a signature from a file
func ReadSignatureFile(sigPath string) ([]byte, error) {
	cleanPath := filepath.Clean(sigPath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}
	return data, nil
}

// WriteSignatureFile writes signature data to a file with secure permissions
func WriteSignatureFile(sigPath string, signatureData []byte) error {
	cleanPath := filepath.Clean(sigPath)
	if err := os.WriteFile(cleanPath, signatureData, signatureFilePerms); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}
	return nil
}

// VerifySignatureFile verifies a signature file for a blob file
// Automatically finds signature file if sigPath is empty
func VerifySignatureFile(ctx context.Context, publicKey crypto.PublicKey, filePath, sigPath string) error {
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Auto-find signature file if not provided
	if sigPath == "" {
		foundSigPath, err := FindSignatureFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to find signature file: %w", err)
		}
		sigPath = foundSigPath
	}

	return verifier.VerifyBlobFile(ctx, filePath, sigPath)
}

// CheckSignatureIntegrity performs integrity checks on a signature
func CheckSignatureIntegrity(signatureData []byte) error {
	// Parse and validate signature format
	artifactSig, err := ParseArtifactSignature(signatureData)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// Validate base64 signature can be decoded
	sigBytes, err := base64.StdEncoding.DecodeString(artifactSig.Base64Signature)
	if err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}

	// Check signature size (Ed25519 signatures are 64 bytes)
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature size: expected %d bytes, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	return nil
}
