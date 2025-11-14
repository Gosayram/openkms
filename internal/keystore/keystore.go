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

// Package keystore provides key storage and management functionality.
package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Gosayram/openkms/internal/storage"
)

const (
	// keyMetadataPrefixLength is the length of "key:metadata:" prefix
	keyMetadataPrefixLength = 14
)

// Store manages key metadata and versions
type Store struct {
	backend storage.Backend
}

// NewStore creates a new keystore
func NewStore(backend storage.Backend) *Store {
	return &Store{
		backend: backend,
	}
}

// CreateKey creates a new key with metadata
func (s *Store) CreateKey(ctx context.Context, metadata *KeyMetadata) error {
	if metadata.ID == "" {
		return fmt.Errorf("key ID is required")
	}

	// Check if key already exists
	existing, err := s.GetKey(ctx, metadata.ID)
	if err == nil && existing != nil {
		return fmt.Errorf("key %s already exists", metadata.ID)
	}

	// Set defaults
	if metadata.State == "" {
		metadata.State = KeyStateCreated
	}
	if metadata.Version == 0 {
		metadata.Version = 1
	}
	now := time.Now()
	if metadata.CreatedAt.IsZero() {
		metadata.CreatedAt = now
	}
	metadata.UpdatedAt = now

	// Store metadata
	return s.saveMetadata(ctx, metadata)
}

// GetKey retrieves key metadata by ID
func (s *Store) GetKey(ctx context.Context, keyID string) (*KeyMetadata, error) {
	key := s.metadataKey(keyID)
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, fmt.Errorf("key %s not found: %w", keyID, err)
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	var metadata KeyMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// UpdateKeyState updates the state of a key
func (s *Store) UpdateKeyState(ctx context.Context, keyID string, newState KeyState) error {
	metadata, err := s.GetKey(ctx, keyID)
	if err != nil {
		return err
	}

	if !IsValidStateTransition(metadata.State, newState) {
		return fmt.Errorf("invalid state transition from %s to %s", metadata.State, newState)
	}

	metadata.State = newState
	metadata.UpdatedAt = time.Now()

	if newState == KeyStateActive && metadata.ActivatedAt == nil {
		now := time.Now()
		metadata.ActivatedAt = &now
	}

	return s.saveMetadata(ctx, metadata)
}

// IncrementVersion increments the version of a key
func (s *Store) IncrementVersion(ctx context.Context, keyID string) (uint64, error) {
	metadata, err := s.GetKey(ctx, keyID)
	if err != nil {
		return 0, err
	}

	metadata.Version++
	metadata.UpdatedAt = time.Now()
	now := time.Now()
	metadata.RotatedAt = &now

	if err := s.saveMetadata(ctx, metadata); err != nil {
		return 0, err
	}

	return metadata.Version, nil
}

// GetKeyVersion retrieves a specific version of a key
func (s *Store) GetKeyVersion(ctx context.Context, keyID string, version uint64) (*KeyVersion, error) {
	key := s.versionKey(keyID, version)
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, fmt.Errorf("key version %s:%d not found: %w", keyID, version, err)
		}
		return nil, fmt.Errorf("failed to get key version: %w", err)
	}

	var keyVersion KeyVersion
	if err := json.Unmarshal(data, &keyVersion); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key version: %w", err)
	}

	return &keyVersion, nil
}

// SaveKeyVersion saves a key version
func (s *Store) SaveKeyVersion(ctx context.Context, keyVersion *KeyVersion) error {
	if keyVersion.KeyID == "" {
		return fmt.Errorf("key ID is required")
	}
	if keyVersion.Version == 0 {
		return fmt.Errorf("version is required")
	}

	if keyVersion.CreatedAt.IsZero() {
		keyVersion.CreatedAt = time.Now()
	}

	key := s.versionKey(keyVersion.KeyID, keyVersion.Version)
	data, err := json.Marshal(keyVersion)
	if err != nil {
		return fmt.Errorf("failed to marshal key version: %w", err)
	}

	return s.backend.Put(ctx, key, data)
}

// ListKeys lists all keys with the given prefix
func (s *Store) ListKeys(ctx context.Context, prefix string) ([]*KeyMetadata, error) {
	searchPrefix := s.metadataKey(prefix)
	keys, err := s.backend.List(ctx, searchPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	var results []*KeyMetadata
	for _, key := range keys {
		// Extract key ID from storage key
		keyID := s.keyIDFromMetadataKey(key)
		metadata, err := s.GetKey(ctx, keyID)
		if err != nil {
			// Skip keys that can't be loaded
			continue
		}
		results = append(results, metadata)
	}

	return results, nil
}

// DeleteKey deletes a key and all its versions
func (s *Store) DeleteKey(ctx context.Context, keyID string) error {
	// First, update state to destroyed
	metadata, err := s.GetKey(ctx, keyID)
	if err != nil {
		return err
	}

	if metadata.State != KeyStateDestroyed {
		if updateErr := s.UpdateKeyState(ctx, keyID, KeyStateDestroyed); updateErr != nil {
			return updateErr
		}
	}

	// Delete metadata
	metaKey := s.metadataKey(keyID)
	if deleteErr := s.backend.Delete(ctx, metaKey); deleteErr != nil && deleteErr != storage.ErrNotFound {
		return fmt.Errorf("failed to delete metadata: %w", deleteErr)
	}

	// Delete all versions
	versionPrefix := s.versionPrefix(keyID)
	versions, err := s.backend.List(ctx, versionPrefix)
	if err == nil {
		for _, versionKey := range versions {
			if err := s.backend.Delete(ctx, versionKey); err != nil {
				// Log but continue
				continue
			}
		}
	}

	return nil
}

// Helper methods

func (s *Store) metadataKey(keyID string) string {
	return fmt.Sprintf("key:metadata:%s", keyID)
}

func (s *Store) versionKey(keyID string, version uint64) string {
	return fmt.Sprintf("key:version:%s:%d", keyID, version)
}

func (s *Store) versionPrefix(keyID string) string {
	return fmt.Sprintf("key:version:%s:", keyID)
}

func (s *Store) keyIDFromMetadataKey(key string) string {
	// Remove "key:metadata:" prefix
	if len(key) > keyMetadataPrefixLength {
		return key[keyMetadataPrefixLength:]
	}
	return key
}

func (s *Store) saveMetadata(ctx context.Context, metadata *KeyMetadata) error {
	key := s.metadataKey(metadata.ID)
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return s.backend.Put(ctx, key, data)
}

// SaveKeyMaterial saves encrypted key material for a specific key version
// The key material should already be encrypted (e.g., with master key)
func (s *Store) SaveKeyMaterial(ctx context.Context, keyID string, version uint64, encryptedMaterial []byte) error {
	if keyID == "" {
		return fmt.Errorf("key ID is required")
	}
	if version == 0 {
		return fmt.Errorf("version is required")
	}

	key := s.keyMaterialKey(keyID, version)
	return s.backend.Put(ctx, key, encryptedMaterial)
}

// GetKeyMaterial retrieves encrypted key material for a specific key version
func (s *Store) GetKeyMaterial(ctx context.Context, keyID string, version uint64) ([]byte, error) {
	key := s.keyMaterialKey(keyID, version)
	data, err := s.backend.Get(ctx, key)
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, fmt.Errorf("key material for %s:%d not found: %w", keyID, version, err)
		}
		return nil, fmt.Errorf("failed to get key material: %w", err)
	}

	return data, nil
}

func (s *Store) keyMaterialKey(keyID string, version uint64) string {
	return fmt.Sprintf("key:material:%s:%d", keyID, version)
}

// RotateKey rotates a key by generating a new version
// This method increments the version and marks the old version as deprecated
func (s *Store) RotateKey(ctx context.Context, keyID string) (uint64, error) {
	metadata, err := s.GetKey(ctx, keyID)
	if err != nil {
		return 0, err
	}

	// Key must be active to rotate
	if metadata.State != KeyStateActive {
		return 0, fmt.Errorf("key must be active to rotate, current state: %s", metadata.State)
	}

	// Increment version
	newVersion, err := s.IncrementVersion(ctx, keyID)
	if err != nil {
		return 0, fmt.Errorf("failed to increment version: %w", err)
	}

	return newVersion, nil
}

// ListKeyVersions lists all versions of a key by checking key material keys
func (s *Store) ListKeyVersions(ctx context.Context, keyID string) ([]uint64, error) {
	// List all key material keys for this key
	materialPrefix := fmt.Sprintf("key:material:%s:", keyID)
	keys, err := s.backend.List(ctx, materialPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list key versions: %w", err)
	}

	var versions []uint64
	for _, key := range keys {
		// Extract version from key: "key:material:{keyID}:{version}"
		// Remove prefix "key:material:{keyID}:"
		if len(key) > len(materialPrefix) {
			versionStr := key[len(materialPrefix):]
			var version uint64
			if _, parseErr := fmt.Sscanf(versionStr, "%d", &version); parseErr == nil {
				versions = append(versions, version)
			}
		}
	}

	return versions, nil
}
