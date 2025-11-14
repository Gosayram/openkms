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

package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// aes256MasterKeySize is the required master key size for AES-256 in bytes
	aes256MasterKeySize = 32
)

// EnvelopeBackend wraps a backend with envelope encryption
// All data is encrypted with the master key before storage
type EnvelopeBackend struct {
	backend   Backend
	masterKey []byte
	aead      cipher.AEAD
}

// NewEnvelopeBackend creates a new envelope encryption wrapper
func NewEnvelopeBackend(backend Backend, masterKey []byte) (*EnvelopeBackend, error) {
	if len(masterKey) != aes256MasterKeySize {
		return nil, fmt.Errorf("master key must be %d bytes (AES-256)", aes256MasterKeySize)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EnvelopeBackend{
		backend:   backend,
		masterKey: masterKey,
		aead:      aead,
	}, nil
}

// decryptData decrypts encrypted data using AEAD cipher
func decryptData(aead cipher.AEAD, encrypted []byte, key string) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Get retrieves and decrypts a value by key
func (e *EnvelopeBackend) Get(ctx context.Context, key string) ([]byte, error) {
	encrypted, err := e.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	return decryptData(e.aead, encrypted, key)
}

// Put encrypts and stores a value with the given key
func (e *EnvelopeBackend) Put(ctx context.Context, key string, value []byte) error {
	// Generate nonce
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := e.aead.Seal(nonce, nonce, value, []byte(key))

	// Store nonce + ciphertext
	return e.backend.Put(ctx, key, ciphertext)
}

// Delete removes a key-value pair
func (e *EnvelopeBackend) Delete(ctx context.Context, key string) error {
	return e.backend.Delete(ctx, key)
}

// List returns all keys with the given prefix
func (e *EnvelopeBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return e.backend.List(ctx, prefix)
}

// Close closes the backend
func (e *EnvelopeBackend) Close() error {
	return e.backend.Close()
}

// Ping checks if the backend is available
func (e *EnvelopeBackend) Ping(ctx context.Context) error {
	return e.backend.Ping(ctx)
}

// Begin starts a new transaction (if supported by underlying backend)
func (e *EnvelopeBackend) Begin(ctx context.Context) (Transaction, error) {
	txBackend, ok := e.backend.(TransactionalBackend)
	if !ok {
		return nil, fmt.Errorf("underlying backend does not support transactions")
	}

	tx, err := txBackend.Begin(ctx)
	if err != nil {
		return nil, err
	}

	return &EnvelopeTransaction{
		tx:    tx,
		aead:  e.aead,
		nonce: make([]byte, e.aead.NonceSize()),
	}, nil
}

// EnvelopeTransaction wraps a transaction with encryption
type EnvelopeTransaction struct {
	tx    Transaction
	aead  cipher.AEAD
	nonce []byte
}

// Get retrieves and decrypts a value by key within the transaction
func (et *EnvelopeTransaction) Get(ctx context.Context, key string) ([]byte, error) {
	encrypted, err := et.tx.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	return decryptData(et.aead, encrypted, key)
}

// Put encrypts and stores a value with the given key within the transaction
func (et *EnvelopeTransaction) Put(ctx context.Context, key string, value []byte) error {
	if _, err := io.ReadFull(rand.Reader, et.nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := et.aead.Seal(et.nonce, et.nonce, value, []byte(key))

	return et.tx.Put(ctx, key, ciphertext)
}

// Delete removes a key-value pair within the transaction
func (et *EnvelopeTransaction) Delete(ctx context.Context, key string) error {
	return et.tx.Delete(ctx, key)
}

// Commit commits the transaction
func (et *EnvelopeTransaction) Commit() error {
	return et.tx.Commit()
}

// Rollback rolls back the transaction
func (et *EnvelopeTransaction) Rollback() error {
	return et.tx.Rollback()
}
