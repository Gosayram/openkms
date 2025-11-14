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

// Package cryptoengine provides cryptographic operations including AES-256-GCM encryption.
package cryptoengine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// aes256KeySize is the key size for AES-256 in bytes (256 bits = 32 bytes)
	aes256KeySize = 32
)

// AES256GCMProvider implements AES-256-GCM encryption
type AES256GCMProvider struct{}

// NewAES256GCMProvider creates a new AES-256-GCM provider
func NewAES256GCMProvider() *AES256GCMProvider {
	return &AES256GCMProvider{}
}

// Algorithm returns the algorithm name
func (p *AES256GCMProvider) Algorithm() string {
	return "AES-256-GCM"
}

// KeySize returns the required key size in bytes (256 bits = 32 bytes)
func (p *AES256GCMProvider) KeySize() int {
	return aes256KeySize
}

// GenerateKey generates a new AES-256 key
func (p *AES256GCMProvider) GenerateKey(r io.Reader) ([]byte, error) {
	key := make([]byte, p.KeySize())
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts data using AES-256-GCM
func (p *AES256GCMProvider) Encrypt(key, plaintext, aad []byte) (*EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	return &EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AAD:        aad,
		Algorithm:  p.Algorithm(),
	}, nil
}

// Decrypt decrypts data using AES-256-GCM
func (p *AES256GCMProvider) Decrypt(key []byte, encrypted *EncryptedData) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(encrypted.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", aead.NonceSize(), len(encrypted.Nonce))
	}

	plaintext, err := aead.Open(nil, encrypted.Nonce, encrypted.Ciphertext, encrypted.AAD)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
