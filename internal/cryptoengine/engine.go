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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

// CryptoEngine implements the Engine interface
type CryptoEngine struct {
	providers        map[string]Provider
	signingProviders map[string]SigningProvider
	hmacProviders    map[string]HMACProvider
	randReader       io.Reader
}

// NewEngine creates a new crypto engine
func NewEngine() *CryptoEngine {
	engine := &CryptoEngine{
		providers:        make(map[string]Provider),
		signingProviders: make(map[string]SigningProvider),
		hmacProviders:    make(map[string]HMACProvider),
		randReader:       rand.Reader,
	}

	// Register default providers
	engine.registerDefaultProviders()

	return engine
}

// registerDefaultProviders registers all default cryptographic providers
func (e *CryptoEngine) registerDefaultProviders() {
	// Encryption providers
	e.RegisterProvider(NewAES256GCMProvider())
	e.RegisterProvider(NewXChaCha20Poly1305Provider())

	// Signing providers
	e.RegisterSigningProvider(NewEd25519Provider())

	// HMAC providers
	e.RegisterHMACProvider(NewHMACSHA256Provider())
}

// RegisterProvider registers a new encryption provider
func (e *CryptoEngine) RegisterProvider(provider Provider) {
	e.providers[provider.Algorithm()] = provider
}

// RegisterSigningProvider registers a new signing provider
func (e *CryptoEngine) RegisterSigningProvider(provider SigningProvider) {
	e.signingProviders[provider.Algorithm()] = provider
}

// RegisterHMACProvider registers a new HMAC provider
func (e *CryptoEngine) RegisterHMACProvider(provider HMACProvider) {
	e.hmacProviders[provider.Algorithm()] = provider
}

// GenerateKey generates a new key for the given algorithm
//
//nolint:revive // ctx parameter is required by Engine interface
func (e *CryptoEngine) GenerateKey(ctx context.Context, algorithm string) ([]byte, error) {
	// Check if it's a signing algorithm
	if provider, ok := e.signingProviders[algorithm]; ok {
		privateKey, _, err := provider.GenerateKey(e.randReader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}

		// Serialize private key
		return serializePrivateKey(algorithm, privateKey)
	}

	// Check if it's an encryption algorithm
	provider, ok := e.providers[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
	}

	return provider.GenerateKey(e.randReader)
}

// Encrypt encrypts plaintext using the given key and algorithm
//
//nolint:revive,gocritic // ctx parameter is required by Engine interface; paramTypeCombine would reduce readability
func (e *CryptoEngine) Encrypt(
	ctx context.Context,
	key []byte,
	algorithm string,
	plaintext []byte,
	aad []byte,
) (*EncryptedData, error) {
	provider, ok := e.providers[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown encryption algorithm: %s", algorithm)
	}

	if len(key) != provider.KeySize() {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", provider.KeySize(), len(key))
	}

	return provider.Encrypt(key, plaintext, aad)
}

// Decrypt decrypts ciphertext using the given key and algorithm
//
//nolint:revive,lll // ctx parameter is required by Engine interface; function signature is necessarily long
func (e *CryptoEngine) Decrypt(
	ctx context.Context,
	key []byte,
	algorithm string,
	encrypted *EncryptedData,
) ([]byte, error) {
	provider, ok := e.providers[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown encryption algorithm: %s", algorithm)
	}

	if len(key) != provider.KeySize() {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", provider.KeySize(), len(key))
	}

	return provider.Decrypt(key, encrypted)
}

// Sign signs data using the given key and algorithm
//
//nolint:revive // ctx parameter is required by Engine interface
func (e *CryptoEngine) Sign(ctx context.Context, key []byte, algorithm string, data []byte) ([]byte, error) {
	provider, ok := e.signingProviders[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown signing algorithm: %s", algorithm)
	}

	// Deserialize private key from bytes
	privateKey, err := deserializePrivateKey(algorithm, key)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	return provider.Sign(privateKey, data)
}

// Verify verifies a signature
//
//nolint:revive,gocritic // ctx parameter is required by Engine interface; paramTypeCombine would reduce readability
func (e *CryptoEngine) Verify(
	ctx context.Context,
	key []byte,
	algorithm string,
	data []byte,
	signature []byte,
) (bool, error) {
	provider, ok := e.signingProviders[algorithm]
	if !ok {
		return false, fmt.Errorf("unknown signing algorithm: %s", algorithm)
	}

	// Deserialize public key from bytes
	publicKey, err := deserializePublicKey(algorithm, key)
	if err != nil {
		return false, fmt.Errorf("failed to deserialize public key: %w", err)
	}

	return provider.Verify(publicKey, data, signature)
}

// HMAC computes HMAC of data using the given key
//
//nolint:revive // ctx parameter is required by Engine interface
func (e *CryptoEngine) HMAC(ctx context.Context, key []byte, algorithm string, data []byte) ([]byte, error) {
	provider, ok := e.hmacProviders[algorithm]
	if !ok {
		return nil, fmt.Errorf("unknown HMAC algorithm: %s", algorithm)
	}

	return provider.HMAC(key, data), nil
}

// VerifyHMAC verifies an HMAC
//
//nolint:revive,gocritic // ctx parameter is required by Engine interface; paramTypeCombine would reduce readability
func (e *CryptoEngine) VerifyHMAC(
	ctx context.Context,
	key []byte,
	algorithm string,
	data []byte,
	mac []byte,
) (bool, error) {
	provider, ok := e.hmacProviders[algorithm]
	if !ok {
		return false, fmt.Errorf("unknown HMAC algorithm: %s", algorithm)
	}

	return provider.VerifyHMAC(key, data, mac), nil
}

// GenerateRandom generates random bytes
//
//nolint:revive // ctx parameter is required by Engine interface
func (e *CryptoEngine) GenerateRandom(ctx context.Context, n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid random byte count: %d", n)
	}

	bytes := make([]byte, n)
	if _, err := io.ReadFull(e.randReader, bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return bytes, nil
}

// Helper functions for key serialization

func deserializePrivateKey(algorithm string, data []byte) (crypto.PrivateKey, error) {
	switch algorithm {
	case algorithmEd25519:
		return DeserializeEd25519PrivateKey(data)
	default:
		return nil, fmt.Errorf("private key deserialization not implemented for %s", algorithm)
	}
}

func deserializePublicKey(algorithm string, data []byte) (crypto.PublicKey, error) {
	switch algorithm {
	case algorithmEd25519:
		return DeserializeEd25519PublicKey(data)
	default:
		return nil, fmt.Errorf("public key deserialization not implemented for %s", algorithm)
	}
}

func serializePrivateKey(algorithm string, key crypto.PrivateKey) ([]byte, error) {
	switch algorithm {
	case algorithmEd25519:
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid private key type for Ed25519")
		}
		return SerializeEd25519PrivateKey(edKey), nil
	default:
		return nil, fmt.Errorf("private key serialization not implemented for %s", algorithm)
	}
}
