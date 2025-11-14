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
	"errors"
)

var (
	// ErrNotFound is returned when a key is not found
	ErrNotFound = errors.New("key not found")
	// ErrAlreadyExists is returned when trying to create a key that already exists
	ErrAlreadyExists = errors.New("key already exists")
)

// Backend defines the interface for storage backends
type Backend interface {
	// Get retrieves a value by key
	Get(ctx context.Context, key string) ([]byte, error)
	// Put stores a value with the given key
	Put(ctx context.Context, key string, value []byte) error
	// Delete removes a key-value pair
	Delete(ctx context.Context, key string) error
	// List returns all keys with the given prefix
	List(ctx context.Context, prefix string) ([]string, error)
	// Close closes the backend and releases resources
	Close() error
	// Ping checks if the backend is available
	Ping(ctx context.Context) error
}

// Transaction represents a storage transaction
type Transaction interface {
	// Get retrieves a value by key within the transaction
	Get(ctx context.Context, key string) ([]byte, error)
	// Put stores a value with the given key within the transaction
	Put(ctx context.Context, key string, value []byte) error
	// Delete removes a key-value pair within the transaction
	Delete(ctx context.Context, key string) error
	// Commit commits the transaction
	Commit() error
	// Rollback rolls back the transaction
	Rollback() error
}

// TransactionalBackend extends Backend with transaction support
type TransactionalBackend interface {
	Backend
	// Begin starts a new transaction
	Begin(ctx context.Context) (Transaction, error)
}
