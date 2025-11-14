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
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEd25519_SignVerify(t *testing.T) {
	provider := NewEd25519Provider()

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	data := []byte("test data to sign")

	// Sign
	signature, err := provider.Sign(privateKey, data)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify
	valid, err := provider.Verify(publicKey, data, signature)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}

	// Verify with wrong data
	valid, _ = provider.Verify(publicKey, []byte("wrong data"), signature)
	if valid {
		t.Error("Signature should not be valid for wrong data")
	}
}

func TestEd25519_SerializeDeserialize(t *testing.T) {
	provider := NewEd25519Provider()

	privateKey, publicKey, _ := provider.GenerateKey(rand.Reader)

	// Serialize private key
	privBytes := SerializeEd25519PrivateKey(privateKey.(ed25519.PrivateKey))
	if len(privBytes) != 64 {
		t.Errorf("Expected private key size 64, got %d", len(privBytes))
	}

	// Deserialize private key
	deserializedPriv, err := DeserializeEd25519PrivateKey(privBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize private key: %v", err)
	}

	// Serialize public key
	pubBytes := SerializeEd25519PublicKey(publicKey.(ed25519.PublicKey))
	if len(pubBytes) != 32 {
		t.Errorf("Expected public key size 32, got %d", len(pubBytes))
	}

	// Deserialize public key
	deserializedPub, err := DeserializeEd25519PublicKey(pubBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize public key: %v", err)
	}

	// Test that deserialized keys work
	data := []byte("test")
	signature, _ := provider.Sign(deserializedPriv, data)
	valid, _ := provider.Verify(deserializedPub, data, signature)

	if !valid {
		t.Error("Deserialized keys should work correctly")
	}
}
