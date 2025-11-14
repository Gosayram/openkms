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

package masterkey

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// aes256MasterKeySize is the required master key size for AES-256 in bytes
	aes256MasterKeySize = 32
	// pbkdf2Iterations is the number of iterations for PBKDF2 key derivation
	pbkdf2Iterations = 100000
	// defaultDirMode is the default directory permissions (read, write, execute for owner only)
	defaultDirMode = 0o700
	// defaultFileMode is the default file permissions (read, write for owner only)
	defaultFileMode = 0o600
	// aesGCMNonceSize is the nonce size for AES-GCM (12 bytes)
	aesGCMNonceSize = 12
)

// FileProvider stores master key encrypted with password in a file
type FileProvider struct {
	filePath string
	password []byte
}

// NewFileProvider creates a new file-based master key provider
func NewFileProvider(filePath string, password []byte) *FileProvider {
	return &FileProvider{
		filePath: filePath,
		password: password,
	}
}

// GetMasterKey retrieves and decrypts the master key from file
//
//nolint:revive // ctx parameter is required by Provider interface
func (f *FileProvider) GetMasterKey(ctx context.Context) ([]byte, error) {
	// Read encrypted key from file
	encryptedHex, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("master key file not found: %w", ErrMasterKeyNotFound)
		}
		return nil, fmt.Errorf("failed to read master key file: %w", err)
	}

	// Decode hex
	encrypted, err := hex.DecodeString(string(encryptedHex))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Extract salt and ciphertext
	if len(encrypted) < aes256MasterKeySize+aesGCMNonceSize {
		return nil, fmt.Errorf("encrypted data too short: %w", ErrInvalidMasterKey)
	}

	salt := encrypted[:aes256MasterKeySize]
	ciphertext := encrypted[aes256MasterKeySize:]

	// Derive key from password using PBKDF2
	key := pbkdf2.Key(f.password, salt, pbkdf2Iterations, aes256MasterKeySize, sha256.New)

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Extract nonce and actual ciphertext
	if len(ciphertext) < aesGCMNonceSize {
		return nil, fmt.Errorf("ciphertext too short: %w", ErrInvalidMasterKey)
	}

	nonce := ciphertext[:aesGCMNonceSize]
	encryptedData := ciphertext[aesGCMNonceSize:]

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	masterKey, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %w", ErrInvalidMasterKey)
	}

	if len(masterKey) != aes256MasterKeySize {
		return nil, fmt.Errorf("invalid master key size: %w", ErrInvalidMasterKey)
	}

	return masterKey, nil
}

// RotateMasterKey generates a new master key and encrypts it
//
//nolint:revive // ctx parameter is required by Provider interface
func (f *FileProvider) RotateMasterKey(ctx context.Context) ([]byte, error) {
	// Generate new master key
	newMasterKey := make([]byte, aes256MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, newMasterKey); err != nil {
		return nil, fmt.Errorf("failed to generate new master key: %w", err)
	}

	// Encrypt and save
	if err := f.saveMasterKey(newMasterKey); err != nil {
		return nil, fmt.Errorf("failed to save new master key: %w", err)
	}

	return newMasterKey, nil
}

// saveMasterKey encrypts and saves the master key to file
func (f *FileProvider) saveMasterKey(masterKey []byte) error {
	// Generate salt
	salt := make([]byte, aes256MasterKeySize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key := pbkdf2.Key(f.password, salt, pbkdf2Iterations, aes256MasterKeySize, sha256.New)

	// Encrypt master key
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, masterKey, nil)

	// Combine salt + ciphertext
	encrypted := make([]byte, 0, len(salt)+len(ciphertext))
	encrypted = append(encrypted, salt...)
	encrypted = append(encrypted, ciphertext...)

	// Encode to hex and save
	encryptedHex := hex.EncodeToString(encrypted)

	// Ensure directory exists
	dir := os.Getenv("OPENKMS_DATA_DIR")
	if dir == "" {
		dir = "./data"
	}
	if err := os.MkdirAll(dir, defaultDirMode); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(f.filePath, []byte(encryptedHex), defaultFileMode); err != nil {
		return fmt.Errorf("failed to write master key file: %w", err)
	}

	return nil
}

// SaveMasterKey is exported for factory use
func (f *FileProvider) SaveMasterKey(masterKey []byte) error {
	return f.saveMasterKey(masterKey)
}

// Close releases resources
func (f *FileProvider) Close() error {
	// Clear password from memory
	for i := range f.password {
		f.password[i] = 0
	}
	return nil
}
