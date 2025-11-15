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

//go:build integration
// +build integration

package masterkey

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
)

// findTPMDevice finds available TPM device for testing
func findTPMDeviceForTest() string {
	paths := []string{
		"/dev/tpmrm0", // Kernel-managed resource manager (preferred)
		"/dev/tpm0",   // Direct TPM access
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func TestTPMProvider_Integration_Basic(t *testing.T) {
	tpmPath := findTPMDeviceForTest()
	if tpmPath == "" {
		t.Skip("TPM device not found. TPM integration tests require a TPM device or emulator.")
	}

	ctx := context.Background()

	config := TPMConfig{
		TPMPath:      tpmPath,
		PCRSelection: nil, // No PCR binding for basic test
		KeyLabel:     "openkms-test-master-key",
		UseSealed:    false,
	}

	// Test 1: Create provider
	provider, err := NewTPMProvider(config)
	if err != nil {
		t.Fatalf("Failed to create TPMProvider: %v", err)
	}
	defer provider.Close()

	// Test 2: GetMasterKey should fail (key is not extractable)
	_, err = provider.GetMasterKey(ctx)
	if err == nil {
		t.Fatal("Expected error when trying to extract master key from TPM")
	}

	// Test 3: WrapKey and UnwrapKey
	testKey := make([]byte, 32) // AES-256 key
	if _, err := rand.Read(testKey); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	wrappedKey, err := provider.WrapKey(ctx, testKey)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	if len(wrappedKey) == 0 {
		t.Fatal("Wrapped key is empty")
	}

	// Unwrap should return original key
	unwrappedKey, err := provider.UnwrapKey(ctx, wrappedKey)
	if err != nil {
		t.Fatalf("Failed to unwrap key: %v", err)
	}

	if len(unwrappedKey) != len(testKey) {
		t.Fatalf("Unwrapped key length mismatch: expected %d, got %d", len(testKey), len(unwrappedKey))
	}

	for i := range testKey {
		if testKey[i] != unwrappedKey[i] {
			t.Fatalf("Key mismatch at index %d: expected %x, got %x", i, testKey[i], unwrappedKey[i])
		}
	}
}

func TestTPMProvider_Integration_WrapUnwrapMultiple(t *testing.T) {
	tpmPath := findTPMDeviceForTest()
	if tpmPath == "" {
		t.Skip("TPM device not found")
	}

	ctx := context.Background()

	config := TPMConfig{
		TPMPath:      tpmPath,
		PCRSelection: nil,
		KeyLabel:     "openkms-test-multi",
		UseSealed:    false,
	}

	provider, err := NewTPMProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	// Test wrapping/unwrapping multiple keys
	for i := 0; i < 10; i++ {
		testKey := make([]byte, 32)
		if _, err := rand.Read(testKey); err != nil {
			t.Fatalf("Failed to generate test key %d: %v", i, err)
		}

		wrappedKey, err := provider.WrapKey(ctx, testKey)
		if err != nil {
			t.Fatalf("Failed to wrap key %d: %v", i, err)
		}

		unwrappedKey, err := provider.UnwrapKey(ctx, wrappedKey)
		if err != nil {
			t.Fatalf("Failed to unwrap key %d: %v", i, err)
		}

		for j := range testKey {
			if testKey[j] != unwrappedKey[j] {
				t.Fatalf("Key %d mismatch at index %d", i, j)
			}
		}
	}
}

func TestTPMProvider_Integration_RotateMasterKey(t *testing.T) {
	tpmPath := findTPMDeviceForTest()
	if tpmPath == "" {
		t.Skip("TPM device not found")
	}

	ctx := context.Background()

	config := TPMConfig{
		TPMPath:      tpmPath,
		PCRSelection: nil,
		KeyLabel:     "openkms-test-rotate",
		UseSealed:    false,
	}

	provider, err := NewTPMProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	defer provider.Close()

	// Test key for wrapping
	testKey := make([]byte, 32)
	if _, err := rand.Read(testKey); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Wrap key with original master key
	oldWrappedKey, err := provider.WrapKey(ctx, testKey)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	// Rotate master key
	_, err = provider.RotateMasterKey(ctx)
	if err != nil {
		t.Fatalf("Failed to rotate master key: %v", err)
	}

	// Old wrapped key should no longer be unwrappable (new primary key)
	// Note: This may or may not fail depending on TPM implementation
	// Some TPMs may allow unwrapping with old key if it's still in memory
	_, err = provider.UnwrapKey(ctx, oldWrappedKey)
	if err == nil {
		t.Log("Warning: Old wrapped key can still be unwrapped after rotation (may be expected behavior)")
	}

	// New master key should work
	newWrappedKey, err := provider.WrapKey(ctx, testKey)
	if err != nil {
		t.Fatalf("Failed to wrap key with new master key: %v", err)
	}

	newUnwrappedKey, err := provider.UnwrapKey(ctx, newWrappedKey)
	if err != nil {
		t.Fatalf("Failed to unwrap key with new master key: %v", err)
	}

	for i := range testKey {
		if testKey[i] != newUnwrappedKey[i] {
			t.Fatalf("Key mismatch after rotation at index %d", i)
		}
	}
}

func TestTPMProvider_Integration_WithPCRSelection(t *testing.T) {
	tpmPath := findTPMDeviceForTest()
	if tpmPath == "" {
		t.Skip("TPM device not found")
	}

	ctx := context.Background()

	// Test with PCR selection (PCRs 0-7)
	config := TPMConfig{
		TPMPath:      tpmPath,
		PCRSelection: []int{0, 1, 2, 3, 4, 5, 6, 7},
		KeyLabel:     "openkms-test-pcr",
		UseSealed:    false,
	}

	provider, err := NewTPMProvider(config)
	if err != nil {
		t.Fatalf("Failed to create provider with PCR selection: %v", err)
	}
	defer provider.Close()

	// Test that it works with PCR selection
	testKey := make([]byte, 32)
	if _, err := rand.Read(testKey); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	wrappedKey, err := provider.WrapKey(ctx, testKey)
	if err != nil {
		t.Fatalf("Failed to wrap key with PCR selection: %v", err)
	}

	unwrappedKey, err := provider.UnwrapKey(ctx, wrappedKey)
	if err != nil {
		t.Fatalf("Failed to unwrap key with PCR selection: %v", err)
	}

	for i := range testKey {
		if testKey[i] != unwrappedKey[i] {
			t.Fatalf("Key mismatch at index %d", i)
		}
	}
}
