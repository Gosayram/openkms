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
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS11Config contains configuration for PKCS#11 provider
type PKCS11Config struct {
	LibraryPath string // Path to PKCS#11 library (e.g., /usr/lib/softhsm/libsofthsm2.so)
	SlotID      uint   // Slot ID (0 = auto-detect)
	TokenLabel  string // Token label (optional, for finding token by label)
	PIN         string // PIN for token authentication
	KeyLabel    string // Label for master key in HSM
	KeyID       string // ID for master key in HSM (optional)
}

// PKCS11Provider implements master key provider using PKCS#11 (HSM)
type PKCS11Provider struct {
	ctx       *pkcs11.Ctx
	slotID    uint
	pin       string
	keyLabel  string
	keyID     string
	keyHandle pkcs11.ObjectHandle
	mu        sync.Mutex // Protects session operations
}

// NewPKCS11Provider creates a new PKCS#11 master key provider
func NewPKCS11Provider(config *PKCS11Config) (*PKCS11Provider, error) {
	if config.LibraryPath == "" {
		return nil, fmt.Errorf("library_path is required for PKCS#11 provider")
	}
	if config.PIN == "" {
		return nil, fmt.Errorf("PIN is required for PKCS#11 provider")
	}
	if config.KeyLabel == "" {
		return nil, fmt.Errorf("key_label is required for PKCS#11 provider")
	}

	// Load PKCS#11 library
	ctx := pkcs11.New(config.LibraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %s", config.LibraryPath)
	}

	// Initialize
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	// Find slot
	slotID := config.SlotID
	if slotID == 0 || config.TokenLabel != "" {
		foundSlotID, err := findSlot(ctx, config.SlotID, config.TokenLabel)
		if err != nil {
			_ = ctx.Finalize() // Best effort cleanup
			return nil, fmt.Errorf("failed to find PKCS#11 slot: %w", err)
		}
		slotID = foundSlotID
	}

	provider := &PKCS11Provider{
		ctx:      ctx,
		slotID:   slotID,
		pin:      config.PIN,
		keyLabel: config.KeyLabel,
		keyID:    config.KeyID,
	}

	// Find or verify master key exists
	if err := provider.findMasterKey(); err != nil {
		_ = ctx.Finalize() // Best effort cleanup
		return nil, fmt.Errorf("failed to find master key in HSM: %w", err)
	}

	return provider, nil
}

// findSlot finds a slot by ID or token label
func findSlot(ctx *pkcs11.Ctx, slotID uint, tokenLabel string) (uint, error) {
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
			//nolint:unconvert,gocritic // Label is a fixed-size array, slice is needed
			if strings.TrimSpace(string(tokenInfo.Label[:])) == tokenLabel {
				return slot, nil
			}
		}
		return 0, fmt.Errorf("token with label '%s' not found", tokenLabel)
	}

	// Use first available slot
	return slots[0], nil
}

// findMasterKey finds the master key object in HSM
func (p *PKCS11Provider) findMasterKey() error {
	session, err := p.openSession()
	if err != nil {
		return err
	}
	defer p.closeSession(session)

	// Build search template
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(p.keyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
	}

	if p.keyID != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(p.keyID)))
	}

	// Find objects
	if initErr := p.ctx.FindObjectsInit(session, template); initErr != nil {
		return fmt.Errorf("failed to init find: %w", initErr)
	}

	handles, _, findErr := p.ctx.FindObjects(session, 1)
	if findErr != nil {
		_ = p.ctx.FindObjectsFinal(session)
		return fmt.Errorf("failed to find objects: %w", findErr)
	}

	if finalErr := p.ctx.FindObjectsFinal(session); finalErr != nil {
		return fmt.Errorf("failed to finalize find: %w", finalErr)
	}

	if len(handles) == 0 {
		return ErrMasterKeyNotFound
	}

	p.keyHandle = handles[0]
	return nil
}

// openSession opens a PKCS#11 session
func (p *PKCS11Provider) openSession() (pkcs11.SessionHandle, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	session, err := p.ctx.OpenSession(p.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}

	// Login
	if err := p.ctx.Login(session, pkcs11.CKU_USER, p.pin); err != nil {
		_ = p.ctx.CloseSession(session)
		return 0, fmt.Errorf("failed to login: %w", err)
	}

	return session, nil
}

// closeSession closes a PKCS#11 session
func (p *PKCS11Provider) closeSession(session pkcs11.SessionHandle) {
	p.mu.Lock()
	defer p.mu.Unlock()

	_ = p.ctx.Logout(session)
	_ = p.ctx.CloseSession(session)
}

// GetMasterKey retrieves the master key
// For HSM, this returns an error because the key is not extractable
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *PKCS11Provider) GetMasterKey(ctx context.Context) ([]byte, error) {
	return nil, fmt.Errorf("master key is stored in HSM and cannot be extracted (use WrapKey/UnwrapKey instead)")
}

// RotateMasterKey generates a new master key in HSM
//
//nolint:revive // ctx parameter is required by Provider interface
func (p *PKCS11Provider) RotateMasterKey(ctx context.Context) ([]byte, error) {
	session, err := p.openSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	// Delete old key if exists
	if p.keyHandle != 0 {
		_ = p.ctx.DestroyObject(session, p.keyHandle)
	}

	// Generate new master key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, aes256MasterKeySize), // 256 bits
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(p.keyLabel)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true), // Store on token
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),    // Key is sensitive
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false), // NOT extractable
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
	}

	if p.keyID != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(p.keyID)))
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	keyHandle, err := p.ctx.GenerateKey(session, mech, template)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key in HSM: %w", err)
	}

	p.keyHandle = keyHandle

	// Return nil since key cannot be extracted
	// The key is now stored in HSM and can be used via WrapKey/UnwrapKey
	return nil, nil
}

// WrapKey encrypts a key using the master key in HSM
//
//nolint:revive,dupl,lll // ctx parameter is required by Provider interface; dupl: similar structure to UnwrapKey is intentional
func (p *PKCS11Provider) WrapKey(ctx context.Context, key []byte) ([]byte, error) {
	session, err := p.openSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	// Initialize encryption with AES-ECB (widely supported)
	// Note: AES-ECB is less secure than AES-GCM, but more widely supported in HSM
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}

	if initErr := p.ctx.EncryptInit(session, mech, p.keyHandle); initErr != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", initErr)
	}

	wrappedKey, encryptErr := p.ctx.Encrypt(session, key)
	if encryptErr != nil {
		return nil, fmt.Errorf("failed to wrap key in HSM: %w", encryptErr)
	}

	return wrappedKey, nil
}

// UnwrapKey decrypts a key using the master key in HSM
//
//nolint:revive,dupl,lll // ctx parameter is required by Provider interface; dupl: similar structure to WrapKey is intentional
func (p *PKCS11Provider) UnwrapKey(ctx context.Context, wrappedKey []byte) ([]byte, error) {
	session, err := p.openSession()
	if err != nil {
		return nil, err
	}
	defer p.closeSession(session)

	// Initialize decryption with AES-ECB
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}

	if initErr := p.ctx.DecryptInit(session, mech, p.keyHandle); initErr != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %w", initErr)
	}

	unwrappedKey, decryptErr := p.ctx.Decrypt(session, wrappedKey)
	if decryptErr != nil {
		return nil, fmt.Errorf("failed to unwrap key in HSM: %w", decryptErr)
	}

	return unwrappedKey, nil
}

// Close releases resources
func (p *PKCS11Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ctx != nil {
		_ = p.ctx.Finalize()
		p.ctx = nil
	}

	// Clear PIN from memory
	pinBytes := []byte(p.pin)
	for i := range pinBytes {
		pinBytes[i] = 0
	}
	p.pin = ""

	return nil
}
