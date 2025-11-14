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
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Poly1305Provider implements XChaCha20-Poly1305 encryption
type XChaCha20Poly1305Provider struct{}

// NewXChaCha20Poly1305Provider creates a new XChaCha20-Poly1305 provider
func NewXChaCha20Poly1305Provider() *XChaCha20Poly1305Provider {
	return &XChaCha20Poly1305Provider{}
}

// Algorithm returns the algorithm name
func (p *XChaCha20Poly1305Provider) Algorithm() string {
	return "XChaCha20-Poly1305"
}

// KeySize returns the required key size in bytes (256 bits = 32 bytes)
func (p *XChaCha20Poly1305Provider) KeySize() int {
	return chacha20poly1305.KeySize
}

// GenerateKey generates a new XChaCha20-Poly1305 key
func (p *XChaCha20Poly1305Provider) GenerateKey(r io.Reader) ([]byte, error) {
	key := make([]byte, p.KeySize())
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts data using XChaCha20-Poly1305
func (p *XChaCha20Poly1305Provider) Encrypt(key, plaintext, aad []byte) (*EncryptedData, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
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

// Decrypt decrypts data using XChaCha20-Poly1305
func (p *XChaCha20Poly1305Provider) Decrypt(key []byte, encrypted *EncryptedData) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
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
