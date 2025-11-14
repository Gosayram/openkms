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
	"context"
	"os"
	"testing"

	"github.com/Gosayram/openkms/internal/storage"
)

func TestStore_CreateAndGetKey(t *testing.T) {
	// Create temporary backend
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, err := storage.NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	store := NewStore(backend)
	ctx := context.Background()

	// Create key
	metadata := &KeyMetadata{
		ID:        "test-key",
		Type:      KeyTypeDEK,
		Algorithm: AlgorithmAES256GCM,
		State:     KeyStateCreated,
	}

	if err := store.CreateKey(ctx, metadata); err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Get key
	retrieved, err := store.GetKey(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if retrieved.ID != metadata.ID {
		t.Errorf("Expected ID %q, got %q", metadata.ID, retrieved.ID)
	}

	if retrieved.Type != metadata.Type {
		t.Errorf("Expected type %q, got %q", metadata.Type, retrieved.Type)
	}
}

func TestStore_UpdateKeyState(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, _ := storage.NewBoltBackend(tmpFile.Name())
	defer backend.Close()

	store := NewStore(backend)
	ctx := context.Background()

	// Create key
	metadata := &KeyMetadata{
		ID:        "test-key",
		Type:      KeyTypeDEK,
		Algorithm: AlgorithmAES256GCM,
		State:     KeyStateCreated,
	}
	store.CreateKey(ctx, metadata)

	// Update state to Active
	if err := store.UpdateKeyState(ctx, "test-key", KeyStateActive); err != nil {
		t.Fatalf("Failed to update state: %v", err)
	}

	// Verify state
	key, _ := store.GetKey(ctx, "test-key")
	if key.State != KeyStateActive {
		t.Errorf("Expected state %q, got %q", KeyStateActive, key.State)
	}

	if key.ActivatedAt == nil {
		t.Error("ActivatedAt should be set when transitioning to Active")
	}
}

func TestStore_InvalidStateTransition(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, _ := storage.NewBoltBackend(tmpFile.Name())
	defer backend.Close()

	store := NewStore(backend)
	ctx := context.Background()

	metadata := &KeyMetadata{
		ID:        "test-key",
		Type:      KeyTypeDEK,
		Algorithm: AlgorithmAES256GCM,
		State:     KeyStateCreated,
	}
	store.CreateKey(ctx, metadata)

	// Try invalid transition: Created -> Deprecated (should fail)
	err = store.UpdateKeyState(ctx, "test-key", KeyStateDeprecated)
	if err == nil {
		t.Error("Expected error for invalid state transition")
	}
}

func TestStore_IncrementVersion(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, _ := storage.NewBoltBackend(tmpFile.Name())
	defer backend.Close()

	store := NewStore(backend)
	ctx := context.Background()

	metadata := &KeyMetadata{
		ID:        "test-key",
		Type:      KeyTypeDEK,
		Algorithm: AlgorithmAES256GCM,
		State:     KeyStateActive,
		Version:   1,
	}
	store.CreateKey(ctx, metadata)

	// Increment version
	newVersion, err := store.IncrementVersion(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to increment version: %v", err)
	}

	if newVersion != 2 {
		t.Errorf("Expected version 2, got %d", newVersion)
	}

	// Verify version was updated
	key, _ := store.GetKey(ctx, "test-key")
	if key.Version != 2 {
		t.Errorf("Expected version 2, got %d", key.Version)
	}

	if key.RotatedAt == nil {
		t.Error("RotatedAt should be set when version is incremented")
	}
}
