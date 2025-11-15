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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// findSoftHSMLibrary finds the SoftHSM2 library path
func findSoftHSMLibrary() string {
	paths := []string{
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/softhsm2/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// setupSoftHSMTestToken sets up a test token for SoftHSM2
// Returns token directory, slot ID, and cleanup function
func setupSoftHSMTestToken(t *testing.T) (string, uint, func()) {
	// Create temporary directory for tokens
	tmpDir, err := os.MkdirTemp("", "softhsm-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	// Set SoftHSM2 config directory
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		cleanup()
		t.Fatalf("Failed to create config directory: %v", err)
	}

	configFile := filepath.Join(configDir, "softhsm2.conf")
	configContent := "directories.tokendir = " + tmpDir + "\n"
	configContent += "objectstore.backend = file\n"
	configContent += "log.level = ERROR\n"

	if err := os.WriteFile(configFile, []byte(configContent), 0o644); err != nil {
		cleanup()
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Set environment variable for SoftHSM2 config
	os.Setenv("SOFTHSM2_CONF", configFile)

	// Initialize token
	tokenLabel := "openkms-test"
	pin := "1234"
	soPin := "5678"

	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", tokenLabel,
		"--pin", pin,
		"--so-pin", soPin)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "SOFTHSM2_CONF="+configFile)

	if err := cmd.Run(); err != nil {
		// Try alternative command (some systems use softhsm2-util without the '2')
		cmd = exec.Command("softhsm2-util", "--init-token", "--free",
			"--label", tokenLabel,
			"--pin", pin,
			"--so-pin", soPin)
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "SOFTHSM2_CONF="+configFile)

		if err := cmd.Run(); err != nil {
			cleanup()
			t.Skipf("Failed to initialize SoftHSM2 token (SoftHSM2 may not be installed): %v", err)
		}
	}

	// Find slot ID
	libraryPath := findSoftHSMLibrary()
	if libraryPath == "" {
		cleanup()
		t.Skip("SoftHSM2 library not found")
	}

	// Use pkcs11-tool to find slot, or try slot 0
	slotID := uint(0)
	cmd = exec.Command("pkcs11-tool", "--module", libraryPath, "--list-slots")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "SOFTHSM2_CONF="+configFile)

	if output, err := cmd.Output(); err == nil {
		// Parse output to find slot with our token
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, tokenLabel) && strings.Contains(line, "Slot") {
				// Try to extract slot number
				// Format: "Slot 0: SoftHSM slot ID 0x..."
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					var id uint
					if _, err := fmt.Sscanf(parts[1], "%d", &id); err == nil {
						slotID = id
						break
					}
				}
			}
		}
	}

	// Store PIN for tests
	t.Setenv("TEST_HSM_PIN", pin)

	return tmpDir, slotID, cleanup
}

// findSlotForTest finds a slot by ID or token label (test helper)
func findSlotForTest(ctx *pkcs11.Ctx, slotID uint, tokenLabel string) (uint, error) {
	slots, err := ctx.GetSlotList(true) // true = only slots with tokens
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return 0, fmt.Errorf("no PKCS#11 slots with tokens found")
	}

	// If slotID is specified, use it
	if slotID != 0 {
		for _, slot := range slots {
			if slot == slotID {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("slot %d not found", slotID)
	}

	// If tokenLabel is specified, find by label
	if tokenLabel != "" {
		for _, slot := range slots {
			tokenInfo, err := ctx.GetTokenInfo(slot)
			if err != nil {
				continue
			}
			if strings.TrimSpace(string(tokenInfo.Label[:])) == tokenLabel {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("token with label '%s' not found", tokenLabel)
	}

	// Use first available slot
	return slots[0], nil
}

// createMasterKeyInHSM creates a master key directly in HSM using PKCS#11 API
// This is a helper function for tests to create keys before creating providers
func createMasterKeyInHSM(t *testing.T, config PKCS11Config) {
	// Load PKCS#11 library
	ctx := pkcs11.New(config.LibraryPath)
	if ctx == nil {
		t.Fatalf("Failed to load PKCS#11 library: %s", config.LibraryPath)
	}

	// Initialize
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("Failed to initialize PKCS#11: %v", err)
	}
	defer ctx.Finalize()

	// Find slot
	slotID := config.SlotID
	if slotID == 0 || config.TokenLabel != "" {
		foundSlotID, err := findSlotForTest(ctx, config.SlotID, config.TokenLabel)
		if err != nil {
			t.Fatalf("Failed to find PKCS#11 slot: %v", err)
		}
		slotID = foundSlotID
	}

	// Open session
	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("Failed to open session: %v", err)
	}
	defer ctx.CloseSession(session)

	// Login
	if err := ctx.Login(session, pkcs11.CKU_USER, config.PIN); err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	defer ctx.Logout(session)

	// Check if key already exists
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(config.KeyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
	}
	if config.KeyID != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(config.KeyID)))
	}

	if err := ctx.FindObjectsInit(session, template); err != nil {
		t.Fatalf("Failed to init find: %v", err)
	}

	handles, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		_ = ctx.FindObjectsFinal(session)
		t.Fatalf("Failed to find objects: %v", err)
	}

	if err := ctx.FindObjectsFinal(session); err != nil {
		t.Fatalf("Failed to finalize find: %v", err)
	}

	if len(handles) > 0 {
		// Key already exists
		return
	}

	// Generate new master key
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), // 256 bits
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(config.KeyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	if config.KeyID != "" {
		keyTemplate = append(keyTemplate, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(config.KeyID)))
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	_, err = ctx.GenerateKey(session, mech, keyTemplate)
	if err != nil {
		t.Fatalf("Failed to generate key in HSM: %v", err)
	}
}

func TestPKCS11Provider_Integration_SoftHSM(t *testing.T) {
	libraryPath := findSoftHSMLibrary()
	if libraryPath == "" {
		t.Skip("SoftHSM2 library not found. Install SoftHSM2 to run integration tests.")
	}

	// Setup test token
	_, slotID, cleanup := setupSoftHSMTestToken(t)
	defer cleanup()

	// Get PIN from environment
	pin := os.Getenv("TEST_HSM_PIN")
	if pin == "" {
		pin = "1234" // Default test PIN
	}

	ctx := context.Background()

	config := PKCS11Config{
		LibraryPath: libraryPath,
		SlotID:      slotID,
		PIN:         pin,
		KeyLabel:    "openkms-master-key",
	}

	// Test 1: Create provider (should fail if key doesn't exist)
	_, err := NewPKCS11Provider(config)
	if err == nil {
		t.Fatal("Expected error when master key doesn't exist")
	}
	if err != ErrMasterKeyNotFound {
		t.Fatalf("Expected ErrMasterKeyNotFound, got: %v", err)
	}

	// Test 2: Create master key in HSM
	createMasterKeyInHSM(t, config)

	// Test 3: Now create provider (key should exist)
	provider, err := NewPKCS11Provider(config)
	if err != nil {
		t.Fatalf("Failed to create PKCS11Provider: %v", err)
	}
	defer provider.Close()

	// Test 4: GetMasterKey should fail (key is not extractable)
	_, err = provider.GetMasterKey(ctx)
	if err == nil {
		t.Fatal("Expected error when trying to extract master key from HSM")
	}

	// Test 5: WrapKey and UnwrapKey
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

	// Test 6: RotateMasterKey
	oldWrappedKey := wrappedKey
	_, err = provider.RotateMasterKey(ctx)
	if err != nil {
		t.Fatalf("Failed to rotate master key: %v", err)
	}

	// Old wrapped key should not unwrap with new master key
	_, err = provider.UnwrapKey(ctx, oldWrappedKey)
	if err == nil {
		t.Fatal("Expected error when unwrapping with old master key")
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

func TestPKCS11Provider_Integration_WrapUnwrapMultiple(t *testing.T) {
	libraryPath := findSoftHSMLibrary()
	if libraryPath == "" {
		t.Skip("SoftHSM2 library not found")
	}

	_, slotID, cleanup := setupSoftHSMTestToken(t)
	defer cleanup()

	pin := os.Getenv("TEST_HSM_PIN")
	if pin == "" {
		pin = "1234"
	}

	ctx := context.Background()

	config := PKCS11Config{
		LibraryPath: libraryPath,
		SlotID:      slotID,
		PIN:         pin,
		KeyLabel:    "openkms-master-key-multi",
	}

	// Create master key in HSM
	createMasterKeyInHSM(t, config)

	// Create provider
	provider, err := NewPKCS11Provider(config)
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

func TestPKCS11Provider_Integration_FindSlotByLabel(t *testing.T) {
	libraryPath := findSoftHSMLibrary()
	if libraryPath == "" {
		t.Skip("SoftHSM2 library not found")
	}

	_, _, cleanup := setupSoftHSMTestToken(t)
	defer cleanup()

	pin := os.Getenv("TEST_HSM_PIN")
	if pin == "" {
		pin = "1234"
	}

	ctx := context.Background()

	config := PKCS11Config{
		LibraryPath: libraryPath,
		SlotID:      0, // Auto-detect
		TokenLabel:  "openkms-test",
		PIN:         pin,
		KeyLabel:    "openkms-master-key-label",
	}

	// Create master key in HSM
	createMasterKeyInHSM(t, config)

	// Test finding slot by token label
	provider, err := NewPKCS11Provider(config)
	if err != nil {
		t.Fatalf("Failed to create provider with token label: %v", err)
	}
	defer provider.Close()

	// Test that it works
	testKey := make([]byte, 32)
	if _, err := rand.Read(testKey); err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	wrappedKey, err := provider.WrapKey(ctx, testKey)
	if err != nil {
		t.Fatalf("Failed to wrap key: %v", err)
	}

	unwrappedKey, err := provider.UnwrapKey(ctx, wrappedKey)
	if err != nil {
		t.Fatalf("Failed to unwrap key: %v", err)
	}

	for i := range testKey {
		if testKey[i] != unwrappedKey[i] {
			t.Fatalf("Key mismatch at index %d", i)
		}
	}
}
