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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
// Returns a JSON-encoded LocalSignedPayload compatible with Cosign v3
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

	// Create a Cosign signature payload (LocalSignedPayload format)
	// Note: Payload field is not part of LocalSignedPayload in v3, we store it separately
	// for verification purposes
	payload := cosign.LocalSignedPayload{
		Base64Signature: base64.StdEncoding.EncodeToString(sig),
	}

	// Create our own structure that includes the payload for verification
	type signedPayload struct {
		cosign.LocalSignedPayload
		Payload []byte `json:"payload,omitempty"` // Include payload for verification
	}

	fullPayload := signedPayload{
		LocalSignedPayload: payload,
		Payload:            blobData,
	}

	// Marshal to JSON
	payloadJSON, err := json.Marshal(fullPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
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
func (v *Verifier) VerifyBlob(ctx context.Context, blob io.Reader, signatureData []byte) error {
	// Parse the signature payload (our custom format with payload included)
	type signedPayload struct {
		cosign.LocalSignedPayload
		Payload []byte `json:"payload,omitempty"`
	}

	var payload signedPayload
	if err := json.Unmarshal(signatureData, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	// Read the blob
	blobData, err := io.ReadAll(blob)
	if err != nil {
		return fmt.Errorf("failed to read blob: %w", err)
	}

	// Verify payload matches blob
	if len(payload.Payload) > 0 && !bytes.Equal(payload.Payload, blobData) {
		return fmt.Errorf("payload does not match blob")
	}

	// Decode signature
	sig, err := base64.StdEncoding.DecodeString(payload.Base64Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create verifier
	verifier, err := signature.LoadVerifier(v.publicKey, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Verify signature
	if err := verifier.VerifySignature(
		bytes.NewReader(sig),
		bytes.NewReader(blobData),
		signatureoptions.WithContext(ctx),
	); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
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
