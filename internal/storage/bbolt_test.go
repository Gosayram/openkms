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
	"os"
	"testing"
)

func TestBoltBackend_BasicOperations(t *testing.T) {
	// Create temporary database
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, err := NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Test Put
	key := "test-key"
	value := []byte("test-value")
	if err := backend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Test Get
	retrieved, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}

	if string(retrieved) != string(value) {
		t.Errorf("Expected %q, got %q", value, retrieved)
	}

	// Test Delete
	if err := backend.Delete(ctx, key); err != nil {
		t.Fatalf("Failed to delete: %v", err)
	}

	// Test Get after delete
	_, err = backend.Get(ctx, key)
	if err != ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestBoltBackend_List(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	backend, err := NewBoltBackend(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Put multiple keys
	keys := []string{"key1", "key2", "key3", "other-key"}
	for _, k := range keys {
		backend.Put(ctx, k, []byte("value"))
	}

	// List with prefix
	list, err := backend.List(ctx, "key")
	if err != nil {
		t.Fatalf("Failed to list: %v", err)
	}

	if len(list) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(list))
	}
}
