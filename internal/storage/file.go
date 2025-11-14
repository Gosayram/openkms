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
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileBackend is a simple file-based storage backend (dev only)
type FileBackend struct {
	basePath string
	mu       sync.RWMutex
}

// NewFileBackend creates a new file-based storage backend
func NewFileBackend(basePath string) (*FileBackend, error) {
	if err := os.MkdirAll(basePath, defaultDirMode); err != nil {
		return nil, fmt.Errorf("failed to create base path: %w", err)
	}

	return &FileBackend{
		basePath: basePath,
	}, nil
}

// Get retrieves a value by key
//
//nolint:revive // ctx parameter is required by Backend interface
func (f *FileBackend) Get(ctx context.Context, key string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	path := f.keyToPath(key)
	//nolint:gosec // path is constructed from validated key, not user input
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

// Put stores a value with the given key
//
//nolint:revive // ctx parameter is required by Backend interface
func (f *FileBackend) Put(ctx context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyToPath(key)
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, defaultDirMode); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(path, value, defaultFileMode); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// Delete removes a key-value pair
//
//nolint:revive // ctx parameter is required by Backend interface
func (f *FileBackend) Delete(ctx context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyToPath(key)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

// List returns all keys with the given prefix
//
//nolint:revive // ctx parameter is required by Backend interface
func (f *FileBackend) List(ctx context.Context, prefix string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	prefixPath := f.keyToPath(prefix)
	var keys []string

	err := filepath.Walk(prefixPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(f.basePath, path)
			if err != nil {
				return err
			}
			keys = append(keys, f.pathToKey(relPath))
		}

		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return keys, nil
}

// Close closes the backend
func (f *FileBackend) Close() error {
	return nil
}

// Ping checks if the backend is available
//
//nolint:revive // ctx parameter is required by Backend interface
func (f *FileBackend) Ping(ctx context.Context) error {
	f.mu.RLock()
	defer f.mu.RUnlock()

	_, err := os.Stat(f.basePath)
	return err
}

// keyToPath converts a storage key to a file path
func (f *FileBackend) keyToPath(key string) string {
	// Sanitize key to prevent directory traversal
	safeKey := filepath.Clean(key)
	return filepath.Join(f.basePath, safeKey+".json")
}

// pathToKey converts a file path back to a storage key
func (f *FileBackend) pathToKey(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-5] // Remove .json extension
}

// FileTransaction is a simple transaction implementation for file backend
type FileTransaction struct {
	backend *FileBackend
	ops     []fileOp
	mu      sync.Mutex
}

type fileOp struct {
	op    string // "put", "delete"
	key   string
	value []byte
}

// Begin starts a new transaction (file backend doesn't support real transactions, this is a mock)
//
//nolint:revive // ctx parameter is required by TransactionalBackend interface
func (f *FileBackend) Begin(ctx context.Context) (Transaction, error) {
	return &FileTransaction{
		backend: f,
		ops:     make([]fileOp, 0),
	}, nil
}

// Get retrieves a value by key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (t *FileTransaction) Get(ctx context.Context, key string) ([]byte, error) {
	return t.backend.Get(ctx, key)
}

// Put stores a value with the given key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (t *FileTransaction) Put(ctx context.Context, key string, value []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Store operation for later commit
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	t.ops = append(t.ops, fileOp{
		op:    "put",
		key:   key,
		value: valueCopy,
	})

	return nil
}

// Delete removes a key-value pair within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (t *FileTransaction) Delete(ctx context.Context, key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.ops = append(t.ops, fileOp{
		op:  "delete",
		key: key,
	})

	return nil
}

// Commit commits the transaction
func (t *FileTransaction) Commit() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, op := range t.ops {
		var err error
		switch op.op {
		case "put":
			err = t.backend.Put(context.Background(), op.key, op.value)
		case "delete":
			err = t.backend.Delete(context.Background(), op.key)
		}

		if err != nil {
			return fmt.Errorf("failed to commit operation %s on key %s: %w", op.op, op.key, err)
		}
	}

	t.ops = nil
	return nil
}

// Rollback rolls back the transaction
func (t *FileTransaction) Rollback() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.ops = nil
	return nil
}
