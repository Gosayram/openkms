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
	"context"
	"crypto"
	"io"
)

// Engine defines the interface for cryptographic operations
type Engine interface {
	// GenerateKey generates a new key for the given algorithm
	GenerateKey(ctx context.Context, algorithm string) ([]byte, error)

	// Encrypt encrypts plaintext using the given key and algorithm
	Encrypt(ctx context.Context, key []byte, algorithm string, plaintext []byte, aad []byte) (*EncryptedData, error)

	// Decrypt decrypts ciphertext using the given key and algorithm
	Decrypt(ctx context.Context, key []byte, algorithm string, encrypted *EncryptedData) ([]byte, error)

	// Sign signs data using the given key and algorithm
	Sign(ctx context.Context, key []byte, algorithm string, data []byte) ([]byte, error)

	// Verify verifies a signature
	Verify(ctx context.Context, key []byte, algorithm string, data []byte, signature []byte) (bool, error)

	// HMAC computes HMAC of data using the given key
	HMAC(ctx context.Context, key []byte, algorithm string, data []byte) ([]byte, error)

	// VerifyHMAC verifies an HMAC
	VerifyHMAC(ctx context.Context, key []byte, algorithm string, data []byte, mac []byte) (bool, error)

	// GenerateRandom generates random bytes
	GenerateRandom(ctx context.Context, n int) ([]byte, error)
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Ciphertext []byte
	Nonce      []byte
	AAD        []byte
	Algorithm  string
}

// Provider represents a specific cryptographic algorithm provider
type Provider interface {
	// Algorithm returns the algorithm name
	Algorithm() string

	// KeySize returns the required key size in bytes
	KeySize() int

	// GenerateKey generates a new key
	GenerateKey(rand io.Reader) ([]byte, error)

	// Encrypt encrypts data
	Encrypt(key []byte, plaintext []byte, aad []byte) (*EncryptedData, error)

	// Decrypt decrypts data
	Decrypt(key []byte, encrypted *EncryptedData) ([]byte, error)
}

// SigningProvider represents a signing algorithm provider
type SigningProvider interface {
	// Algorithm returns the algorithm name
	Algorithm() string

	// KeySize returns the required key size in bytes
	KeySize() int

	// GenerateKey generates a new key pair
	GenerateKey(rand io.Reader) (crypto.PrivateKey, crypto.PublicKey, error)

	// Sign signs data
	Sign(privateKey crypto.PrivateKey, data []byte) ([]byte, error)

	// Verify verifies a signature
	Verify(publicKey crypto.PublicKey, data []byte, signature []byte) (bool, error)
}

// HMACProvider represents an HMAC algorithm provider
type HMACProvider interface {
	// Algorithm returns the algorithm name
	Algorithm() string

	// KeySize returns the recommended key size in bytes
	KeySize() int

	// HMAC computes HMAC
	HMAC(key []byte, data []byte) []byte

	// VerifyHMAC verifies an HMAC
	VerifyHMAC(key []byte, data []byte, mac []byte) bool
}
