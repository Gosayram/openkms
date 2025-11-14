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
	"testing"
)

func TestAES256GCM_EncryptDecrypt(t *testing.T) {
	provider := NewAES256GCMProvider()

	// Generate key
	key, err := provider.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key size 32, got %d", len(key))
	}

	// Test encryption/decryption
	plaintext := []byte("test plaintext data")
	aad := []byte("additional authenticated data")

	encrypted, err := provider.Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	if len(encrypted.Nonce) == 0 {
		t.Error("Nonce is empty")
	}

	// Test decryption
	decrypted, err := provider.Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data doesn't match. Expected %q, got %q", plaintext, decrypted)
	}
}

func TestAES256GCM_KeySize(t *testing.T) {
	provider := NewAES256GCMProvider()

	if provider.KeySize() != 32 {
		t.Errorf("Expected key size 32, got %d", provider.KeySize())
	}
}

func TestAES256GCM_DifferentNonces(t *testing.T) {
	provider := NewAES256GCMProvider()

	key, _ := provider.GenerateKey(rand.Reader)
	plaintext := []byte("test")

	encrypted1, _ := provider.Encrypt(key, plaintext, nil)
	encrypted2, _ := provider.Encrypt(key, plaintext, nil)

	// Nonces should be different
	if string(encrypted1.Nonce) == string(encrypted2.Nonce) {
		t.Error("Nonces should be different for each encryption")
	}

	// Both should decrypt correctly
	decrypted1, _ := provider.Decrypt(key, encrypted1)
	decrypted2, _ := provider.Decrypt(key, encrypted2)

	if string(decrypted1) != string(plaintext) || string(decrypted2) != string(plaintext) {
		t.Error("Both encryptions should decrypt correctly")
	}
}
