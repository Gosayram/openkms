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

// Package storage provides storage backends including bbolt (BoltDB) implementation.
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

const (
	// defaultDirMode is the default directory permissions (read, write, execute for owner only)
	defaultDirMode = 0o700
	// defaultFileMode is the default file permissions (read, write for owner only)
	defaultFileMode = 0o600
)

// BoltBackend is a bbolt-based storage backend
type BoltBackend struct {
	db *bbolt.DB
}

// NewBoltBackend creates a new bbolt-based storage backend
func NewBoltBackend(path string) (*BoltBackend, error) {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, defaultDirMode); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	db, err := bbolt.Open(path, defaultFileMode, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open bbolt database: %w", err)
	}

	// Create default bucket if it doesn't exist
	err = db.Update(func(tx *bbolt.Tx) error {
		_, updateErr := tx.CreateBucketIfNotExists([]byte("data"))
		return updateErr
	})

	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	return &BoltBackend{
		db: db,
	}, nil
}

// Get retrieves a value by key
//
//nolint:revive // ctx parameter is required by Backend interface
func (b *BoltBackend) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("data"))
		if bucket == nil {
			return ErrNotFound
		}

		val := bucket.Get([]byte(key))
		if val == nil {
			return ErrNotFound
		}

		// Copy the value since it's only valid within the transaction
		value = make([]byte, len(val))
		copy(value, val)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return value, nil
}

// Put stores a value with the given key
//
//nolint:revive // ctx parameter is required by Backend interface
func (b *BoltBackend) Put(ctx context.Context, key string, value []byte) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("data"))
		if bucket == nil {
			return fmt.Errorf("bucket 'data' does not exist")
		}

		return bucket.Put([]byte(key), value)
	})
}

// Delete removes a key-value pair
//
//nolint:revive // ctx parameter is required by Backend interface
func (b *BoltBackend) Delete(ctx context.Context, key string) error {
	return b.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("data"))
		if bucket == nil {
			return ErrNotFound
		}

		val := bucket.Get([]byte(key))
		if val == nil {
			return ErrNotFound
		}

		return bucket.Delete([]byte(key))
	})
}

// List returns all keys with the given prefix
//
//nolint:revive // ctx parameter is required by Backend interface
func (b *BoltBackend) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string

	err := b.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("data"))
		if bucket == nil {
			return nil
		}

		prefixBytes := []byte(prefix)
		c := bucket.Cursor()

		//nolint:lll // cursor iteration requires long condition for prefix matching
		for k, _ := c.Seek(prefixBytes); k != nil && len(k) >= len(prefixBytes) && string(k[:len(prefixBytes)]) == prefix; k, _ = c.Next() {
			keys = append(keys, string(k))
		}

		return nil
	})

	return keys, err
}

// Close closes the backend
func (b *BoltBackend) Close() error {
	return b.db.Close()
}

// Ping checks if the backend is available
func (b *BoltBackend) Ping(_ context.Context) error {
	return b.db.View(func(_ *bbolt.Tx) error {
		return nil
	})
}

// Begin starts a new transaction
//
//nolint:revive // ctx parameter is required by TransactionalBackend interface
func (b *BoltBackend) Begin(ctx context.Context) (Transaction, error) {
	tx, err := b.db.Begin(true)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &BoltTransaction{
		tx:     tx,
		bucket: []byte("data"),
	}, nil
}

// BoltTransaction implements Transaction for bbolt
type BoltTransaction struct {
	tx     *bbolt.Tx
	bucket []byte
}

// Get retrieves a value by key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (bt *BoltTransaction) Get(ctx context.Context, key string) ([]byte, error) {
	bucket := bt.tx.Bucket(bt.bucket)
	if bucket == nil {
		return nil, ErrNotFound
	}

	val := bucket.Get([]byte(key))
	if val == nil {
		return nil, ErrNotFound
	}

	// Copy the value
	value := make([]byte, len(val))
	copy(value, val)

	return value, nil
}

// Put stores a value with the given key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (bt *BoltTransaction) Put(ctx context.Context, key string, value []byte) error {
	bucket := bt.tx.Bucket(bt.bucket)
	if bucket == nil {
		return fmt.Errorf("bucket does not exist")
	}

	return bucket.Put([]byte(key), value)
}

// Delete removes a key-value pair within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (bt *BoltTransaction) Delete(ctx context.Context, key string) error {
	bucket := bt.tx.Bucket(bt.bucket)
	if bucket == nil {
		return ErrNotFound
	}

	val := bucket.Get([]byte(key))
	if val == nil {
		return ErrNotFound
	}

	return bucket.Delete([]byte(key))
}

// Commit commits the transaction
func (bt *BoltTransaction) Commit() error {
	return bt.tx.Commit()
}

// Rollback rolls back the transaction
func (bt *BoltTransaction) Rollback() error {
	return bt.tx.Rollback()
}
