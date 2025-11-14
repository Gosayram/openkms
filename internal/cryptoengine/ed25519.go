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

package cryptoengine

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
)

const algorithmEd25519 = "Ed25519"

// Ed25519Provider implements Ed25519 signing
type Ed25519Provider struct{}

// NewEd25519Provider creates a new Ed25519 provider
func NewEd25519Provider() *Ed25519Provider {
	return &Ed25519Provider{}
}

// Algorithm returns the algorithm name
func (p *Ed25519Provider) Algorithm() string {
	return algorithmEd25519
}

// KeySize returns the key size (Ed25519 private key is 64 bytes, public is 32)
func (p *Ed25519Provider) KeySize() int {
	return ed25519.PrivateKeySize // 64 bytes for private key
}

// GenerateKey generates a new Ed25519 key pair
func (p *Ed25519Provider) GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	return privateKey, publicKey, nil
}

// Sign signs data using Ed25519
func (p *Ed25519Provider) Sign(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	edKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type for Ed25519")
	}

	signature := ed25519.Sign(edKey, data)
	return signature, nil
}

// Verify verifies an Ed25519 signature
func (p *Ed25519Provider) Verify(publicKey crypto.PublicKey, data, signature []byte) (bool, error) {
	edKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("invalid public key type for Ed25519")
	}

	return ed25519.Verify(edKey, data, signature), nil
}

// SerializeEd25519PrivateKey serializes an Ed25519 private key to bytes
func SerializeEd25519PrivateKey(key ed25519.PrivateKey) []byte {
	// Ed25519 private key is already a byte slice
	return key
}

// DeserializeEd25519PrivateKey deserializes bytes to an Ed25519 private key
func DeserializeEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", ed25519.PrivateKeySize, len(data))
	}
	return ed25519.PrivateKey(data), nil
}

// SerializeEd25519PublicKey serializes an Ed25519 public key to bytes
func SerializeEd25519PublicKey(key ed25519.PublicKey) []byte {
	// Ed25519 public key is already a byte slice
	return key
}

// DeserializeEd25519PublicKey deserializes bytes to an Ed25519 public key
func DeserializeEd25519PublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(data))
	}
	return ed25519.PublicKey(data), nil
}
