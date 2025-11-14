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
	"crypto/rand"
	"os"
	"testing"
)

func TestEnvelopeBackend_Encryption(t *testing.T) {
	// Create master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	// Create temporary backend
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	baseBackend, err := NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer baseBackend.Close()

	// Wrap with envelope encryption
	envelopeBackend, err := NewEnvelopeBackend(baseBackend, masterKey)
	if err != nil {
		t.Fatalf("Failed to create envelope backend: %v", err)
	}

	ctx := context.Background()

	// Test Put/Get
	key := "test-key"
	value := []byte("sensitive data")

	if err := envelopeBackend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Verify data is encrypted in underlying storage
	rawData, err := baseBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get raw data: %v", err)
	}

	// Raw data should be different from plaintext
	if string(rawData) == string(value) {
		t.Error("Data should be encrypted in storage")
	}

	// Test Get (decryption)
	retrieved, err := envelopeBackend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("Expected %q, got %q", value, retrieved)
	}
}

func TestEnvelopeBackend_DifferentNonces(t *testing.T) {
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	baseBackend, _ := NewBoltBackend(tmpFile.Name())
	defer baseBackend.Close()

	envelopeBackend, _ := NewEnvelopeBackend(baseBackend, masterKey)
	ctx := context.Background()

	key := "test-key"
	value := []byte("test value")

	// Put same value twice
	envelopeBackend.Put(ctx, key, value)
	raw1, _ := baseBackend.Get(ctx, key)

	envelopeBackend.Delete(ctx, key)
	envelopeBackend.Put(ctx, key, value)
	raw2, _ := baseBackend.Get(ctx, key)

	// Encrypted values should be different (different nonces)
	if string(raw1) == string(raw2) {
		t.Error("Encrypted values should be different due to different nonces")
	}

	// But both should decrypt to same value
	decrypted1, _ := envelopeBackend.Get(ctx, key)
	envelopeBackend.Delete(ctx, key)
	envelopeBackend.Put(ctx, key, value)
	decrypted2, _ := envelopeBackend.Get(ctx, key)

	if string(decrypted1) != string(value) || string(decrypted2) != string(value) {
		t.Error("Both encryptions should decrypt to same value")
	}
}
