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
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// skipIfEtcdUnavailable skips the test if etcd is not available
func skipIfEtcdUnavailable(t *testing.T) {
	t.Helper()

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Skipf("etcd not available: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Status(ctx, "localhost:2379")
	if err != nil {
		t.Skipf("etcd not available: %v", err)
	}
}

func TestEtcdBackend_BasicOperations(t *testing.T) {
	skipIfEtcdUnavailable(t)

	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
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
		t.Fatalf("Expected %s, got %s", string(value), string(retrieved))
	}

	// Test Get non-existent key
	_, err = backend.Get(ctx, "non-existent")
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}

	// Test Delete
	if err := backend.Delete(ctx, key); err != nil {
		t.Fatalf("Failed to delete: %v", err)
	}

	// Test Delete non-existent key
	err = backend.Delete(ctx, "non-existent")
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got %v", err)
	}
}

func TestEtcdBackend_List(t *testing.T) {
	skipIfEtcdUnavailable(t)

	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Put some keys with prefix
	keys := []string{"prefix/key1", "prefix/key2", "prefix/key3", "other/key1"}
	for _, key := range keys {
		if err := backend.Put(ctx, key, []byte("value")); err != nil {
			t.Fatalf("Failed to put %s: %v", key, err)
		}
	}
	defer func() {
		// Cleanup
		for _, key := range keys {
			_ = backend.Delete(ctx, key)
		}
	}()

	// List keys with prefix
	list, err := backend.List(ctx, "prefix/")
	if err != nil {
		t.Fatalf("Failed to list: %v", err)
	}

	if len(list) != 3 {
		t.Fatalf("Expected 3 keys, got %d: %v", len(list), list)
	}

	// Check that all keys have the prefix
	for _, key := range list {
		if !hasPrefix(key, "prefix/") {
			t.Fatalf("Key %s does not have prefix 'prefix/'", key)
		}
	}
}

func TestEtcdBackend_Ping(t *testing.T) {
	skipIfEtcdUnavailable(t)

	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	if err := backend.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestEtcdBackend_Transaction(t *testing.T) {
	skipIfEtcdUnavailable(t)

	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Begin transaction
	tx, err := backend.Begin(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Put in transaction
	key1 := "tx-key1"
	value1 := []byte("tx-value1")
	if err := tx.Put(ctx, key1, value1); err != nil {
		t.Fatalf("Failed to put in transaction: %v", err)
	}

	// Get in transaction
	retrieved, err := tx.Get(ctx, key1)
	if err != nil {
		t.Fatalf("Failed to get in transaction: %v", err)
	}
	if string(retrieved) != string(value1) {
		t.Fatalf("Expected %s, got %s", string(value1), string(retrieved))
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// Verify value is persisted
	retrieved, err = backend.Get(ctx, key1)
	if err != nil {
		t.Fatalf("Failed to get after commit: %v", err)
	}
	if string(retrieved) != string(value1) {
		t.Fatalf("Expected %s, got %s", string(value1), string(retrieved))
	}

	// Cleanup
	_ = backend.Delete(ctx, key1)
}

func TestEtcdBackend_TransactionRollback(t *testing.T) {
	skipIfEtcdUnavailable(t)

	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Begin transaction
	tx, err := backend.Begin(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Put in transaction
	key1 := "tx-rollback-key1"
	value1 := []byte("tx-rollback-value1")
	if err := tx.Put(ctx, key1, value1); err != nil {
		t.Fatalf("Failed to put in transaction: %v", err)
	}

	// Rollback transaction
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Failed to rollback transaction: %v", err)
	}

	// Verify value is not persisted
	_, err = backend.Get(ctx, key1)
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound after rollback, got %v", err)
	}
}

func TestEtcdBackend_Watch(t *testing.T) {
	skipIfEtcdUnavailable(t)

	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start watching
	watchChan, err := backend.Watch(ctx, "watch-prefix/")
	if err != nil {
		t.Fatalf("Failed to start watch: %v", err)
	}

	// Put a key that matches the prefix
	key := "watch-prefix/test-key"
	value := []byte("watch-value")
	go func() {
		time.Sleep(100 * time.Millisecond)
		if err := backend.Put(ctx, key, value); err != nil {
			t.Errorf("Failed to put in watch test: %v", err)
		}
	}()

	// Wait for watch event
	select {
	case event := <-watchChan:
		if event.Type != "PUT" {
			t.Fatalf("Expected PUT event, got %s", event.Type)
		}
		if event.Key != key {
			t.Fatalf("Expected key %s, got %s", key, event.Key)
		}
		if string(event.Value) != string(value) {
			t.Fatalf("Expected value %s, got %s", string(value), string(event.Value))
		}
	case <-ctx.Done():
		t.Fatal("Watch timeout")
	}

	// Cleanup
	_ = backend.Delete(ctx, key)
}

func TestEtcdBackend_ClusterSupport(t *testing.T) {
	skipIfEtcdUnavailable(t)

	// Test with multiple endpoints (even if they point to the same server)
	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:      []string{"localhost:2379", "localhost:2379"},
		DialTimeout:    5 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create backend with multiple endpoints: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Test basic operation
	key := "cluster-test-key"
	value := []byte("cluster-test-value")
	if err := backend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	retrieved, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}
	if string(retrieved) != string(value) {
		t.Fatalf("Expected %s, got %s", string(value), string(retrieved))
	}

	// Cleanup
	_ = backend.Delete(ctx, key)
}

func TestEtcdBackend_RetryOnFailure(t *testing.T) {
	skipIfEtcdUnavailable(t)

	// This test verifies that retry logic is in place
	// In a real scenario, we would need to simulate connection failures
	backend, err := NewEtcdBackend(EtcdConfig{
		Endpoints:        []string{"localhost:2379"},
		DialTimeout:      5 * time.Second,
		RequestTimeout:   3 * time.Second,
		RetryMaxAttempts: 3,
		RetryBackoff:     100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Test that operations work with retry configuration
	key := "retry-test-key"
	value := []byte("retry-test-value")
	if err := backend.Put(ctx, key, value); err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	retrieved, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Failed to get: %v", err)
	}
	if string(retrieved) != string(value) {
		t.Fatalf("Expected %s, got %s", string(value), string(retrieved))
	}

	// Cleanup
	_ = backend.Delete(ctx, key)
}

// Helper function to check if a string has a prefix
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
