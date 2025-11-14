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

package keystore

import (
	"time"
)

// KeyType represents the type of a key
type KeyType string

const (
	// KeyTypeMasterKey is the root master key
	KeyTypeMasterKey KeyType = "master-key"
	// KeyTypeKEK is a key encryption key
	KeyTypeKEK KeyType = "kek"
	// KeyTypeDEK is a data encryption key
	KeyTypeDEK KeyType = "dek"
	// KeyTypeSigning is a signing key
	KeyTypeSigning KeyType = "signing-key"
	// KeyTypeHMAC is an HMAC key
	KeyTypeHMAC KeyType = "hmac-key"
)

// KeyState represents the lifecycle state of a key
type KeyState string

const (
	// KeyStateCreated means the key is created but not active
	KeyStateCreated KeyState = "created"
	// KeyStateActive means the key is active and can be used
	KeyStateActive KeyState = "active"
	// KeyStateDeprecated means the key can be used for decryption but not encryption
	KeyStateDeprecated KeyState = "deprecated"
	// KeyStateDisabled means the key is disabled and cannot be used
	KeyStateDisabled KeyState = "disabled"
	// KeyStateDestroyed means the key is permanently destroyed
	KeyStateDestroyed KeyState = "destroyed"
)

// Algorithm represents the cryptographic algorithm
type Algorithm string

const (
	// AlgorithmAES256GCM is AES-256-GCM
	AlgorithmAES256GCM Algorithm = "AES-256-GCM"
	// AlgorithmXChaCha20Poly1305 is XChaCha20-Poly1305
	AlgorithmXChaCha20Poly1305 Algorithm = "XChaCha20-Poly1305"
	// AlgorithmEd25519 is Ed25519 for signing
	AlgorithmEd25519 Algorithm = "Ed25519"
	// AlgorithmHMACSHA256 is HMAC-SHA-256
	AlgorithmHMACSHA256 Algorithm = "HMAC-SHA-256"
)

// KeyMetadata represents metadata about a key
type KeyMetadata struct {
	ID          string     `json:"id"`
	Type        KeyType    `json:"type"`
	Algorithm   Algorithm  `json:"algorithm"`
	State       KeyState   `json:"state"`
	Version     uint64     `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
	// Policy contains rotation and usage policies
	Policy *KeyPolicy `json:"policy,omitempty"`
}

// KeyPolicy defines policies for key usage and rotation
type KeyPolicy struct {
	// RotationPolicy defines when the key should be rotated
	RotationPolicy *RotationPolicy `json:"rotation_policy,omitempty"`
	// AllowedOperations defines which operations are allowed
	AllowedOperations []string `json:"allowed_operations,omitempty"`
}

// RotationPolicy defines key rotation rules
type RotationPolicy struct {
	// TimeBased rotation interval
	TimeBased *TimeBasedRotation `json:"time_based,omitempty"`
	// UsageBased rotation after N operations
	UsageBased *UsageBasedRotation `json:"usage_based,omitempty"`
}

// TimeBasedRotation rotates keys after a time interval
type TimeBasedRotation struct {
	Interval time.Duration `json:"interval"`
}

// UsageBasedRotation rotates keys after N operations
type UsageBasedRotation struct {
	MaxOperations uint64 `json:"max_operations"`
}

// KeyVersion represents a specific version of a key
type KeyVersion struct {
	KeyID     string    `json:"key_id"`
	Version   uint64    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	State     KeyState  `json:"state"`
	Encrypted bool      `json:"encrypted"` // Whether the key material is encrypted
}

// IsValidStateTransition checks if a state transition is valid
func IsValidStateTransition(from, to KeyState) bool {
	validTransitions := map[KeyState][]KeyState{
		KeyStateCreated:    {KeyStateActive, KeyStateDisabled, KeyStateDestroyed},
		KeyStateActive:     {KeyStateDeprecated, KeyStateDisabled, KeyStateDestroyed},
		KeyStateDeprecated: {KeyStateDisabled, KeyStateDestroyed},
		KeyStateDisabled:   {KeyStateActive, KeyStateDestroyed},
		KeyStateDestroyed:  {}, // No transitions from destroyed
	}

	allowed, ok := validTransitions[from]
	if !ok {
		return false
	}

	for _, state := range allowed {
		if state == to {
			return true
		}
	}

	return false
}

// CanEncrypt checks if a key can be used for encryption
func (km *KeyMetadata) CanEncrypt() bool {
	return km.State == KeyStateActive
}

// CanDecrypt checks if a key can be used for decryption
func (km *KeyMetadata) CanDecrypt() bool {
	return km.State == KeyStateActive || km.State == KeyStateDeprecated
}

// CanSign checks if a key can be used for signing
func (km *KeyMetadata) CanSign() bool {
	return km.State == KeyStateActive && (km.Type == KeyTypeSigning || km.Type == KeyTypeHMAC)
}
