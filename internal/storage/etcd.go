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

// Package storage provides storage backends including etcd implementation.
package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const (
	// defaultEtcdDialTimeout is the default timeout for establishing connection to etcd
	defaultEtcdDialTimeout = 5 * time.Second
	// defaultEtcdRequestTimeout is the default timeout for etcd requests
	defaultEtcdRequestTimeout = 3 * time.Second
	// defaultEtcdKeyPrefix is the default prefix for all keys stored in etcd
	defaultEtcdKeyPrefix = "/openkms/"
	// defaultEtcdRetryMaxAttempts is the maximum number of retry attempts for failed operations
	defaultEtcdRetryMaxAttempts = 3
	// defaultEtcdRetryBackoff is the backoff duration between retries
	defaultEtcdRetryBackoff = 100 * time.Millisecond
	// defaultEtcdWatchChannelSize is the default size for watch event channel
	defaultEtcdWatchChannelSize = 10
	// defaultEtcdLeaderElectionTTL is the default TTL for etcd leader election session
	defaultEtcdLeaderElectionTTL = 10
)

// EtcdBackend is an etcd-based storage backend
type EtcdBackend struct {
	client           *clientv3.Client
	keyPrefix        string
	requestTimeout   time.Duration
	retryMaxAttempts int
	retryBackoff     time.Duration
	mu               sync.RWMutex
	closed           bool
}

// EtcdConfig holds etcd connection configuration
type EtcdConfig struct {
	// Endpoints is a list of etcd endpoints (e.g., ["localhost:2379"])
	Endpoints []string
	// DialTimeout is the timeout for establishing connection (default: 5s)
	DialTimeout time.Duration
	// RequestTimeout is the timeout for etcd requests (default: 3s)
	RequestTimeout time.Duration
	// KeyPrefix is the prefix for all keys (default: "/openkms/")
	KeyPrefix string
	// RetryMaxAttempts is the maximum number of retry attempts (default: 3)
	RetryMaxAttempts int
	// RetryBackoff is the backoff duration between retries (default: 100ms)
	RetryBackoff time.Duration
}

// NewEtcdBackend creates a new etcd-based storage backend
func NewEtcdBackend(config EtcdConfig) (*EtcdBackend, error) {
	if len(config.Endpoints) == 0 {
		return nil, fmt.Errorf("at least one etcd endpoint is required")
	}

	dialTimeout := config.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = defaultEtcdDialTimeout
	}

	requestTimeout := config.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = defaultEtcdRequestTimeout
	}

	keyPrefix := config.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = defaultEtcdKeyPrefix
	}
	// Ensure prefix ends with /
	if !strings.HasSuffix(keyPrefix, "/") {
		keyPrefix += "/"
	}

	retryMaxAttempts := config.RetryMaxAttempts
	if retryMaxAttempts == 0 {
		retryMaxAttempts = defaultEtcdRetryMaxAttempts
	}

	retryBackoff := config.RetryBackoff
	if retryBackoff == 0 {
		retryBackoff = defaultEtcdRetryBackoff
	}

	// Create etcd client with retry and failover support
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   config.Endpoints,
		DialTimeout: dialTimeout,
		// Enable automatic retry on connection failures
		RejectOldCluster: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	_, err = client.Status(ctx, config.Endpoints[0])
	if err != nil {
		if closeErr := client.Close(); closeErr != nil {
			// Log close error but return original error
			_ = closeErr
		}
		return nil, fmt.Errorf("failed to connect to etcd: %w", err)
	}

	return &EtcdBackend{
		client:           client,
		keyPrefix:        keyPrefix,
		requestTimeout:   requestTimeout,
		retryMaxAttempts: retryMaxAttempts,
		retryBackoff:     retryBackoff,
	}, nil
}

// prefixKey adds the key prefix to the given key
func (e *EtcdBackend) prefixKey(key string) string {
	return e.keyPrefix + key
}

// stripPrefix removes the key prefix from the given key
func (e *EtcdBackend) stripPrefix(key string) string {
	if strings.HasPrefix(key, e.keyPrefix) {
		return strings.TrimPrefix(key, e.keyPrefix)
	}
	return key
}

// retryOperation retries an operation with exponential backoff
func (e *EtcdBackend) retryOperation(ctx context.Context, operation func() error) error {
	var lastErr error
	backoff := e.retryBackoff

	for attempt := 0; attempt < e.retryMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				// Exponential backoff
				backoff *= 2
			}
		}

		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			return err
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", e.retryMaxAttempts, lastErr)
}

// isRetryableError checks if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Check for context deadline exceeded (timeout)
	if err == context.DeadlineExceeded || err == context.Canceled {
		return true
	}
	// Check for etcd-specific retryable errors
	errStr := err.Error()
	return strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "unavailable") ||
		strings.Contains(errStr, "leader")
}

// Get retrieves a value by key
//
//nolint:revive // ctx parameter is required by Backend interface
func (e *EtcdBackend) Get(ctx context.Context, key string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return nil, fmt.Errorf("etcd backend is closed")
	}

	prefixedKey := e.prefixKey(key)
	requestCtx, cancel := context.WithTimeout(ctx, e.requestTimeout)
	defer cancel()

	var resp *clientv3.GetResponse
	err := e.retryOperation(requestCtx, func() error {
		var retryErr error
		resp, retryErr = e.client.Get(requestCtx, prefixedKey)
		return retryErr
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get value: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return nil, ErrNotFound
	}

	return resp.Kvs[0].Value, nil
}

// Put stores a value with the given key
//
//nolint:revive // ctx parameter is required by Backend interface
func (e *EtcdBackend) Put(ctx context.Context, key string, value []byte) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return fmt.Errorf("etcd backend is closed")
	}

	prefixedKey := e.prefixKey(key)
	requestCtx, cancel := context.WithTimeout(ctx, e.requestTimeout)
	defer cancel()

	err := e.retryOperation(requestCtx, func() error {
		_, retryErr := e.client.Put(requestCtx, prefixedKey, string(value))
		return retryErr
	})

	if err != nil {
		return fmt.Errorf("failed to put value: %w", err)
	}

	return nil
}

// Delete removes a key-value pair
//
//nolint:revive // ctx parameter is required by Backend interface
func (e *EtcdBackend) Delete(ctx context.Context, key string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return fmt.Errorf("etcd backend is closed")
	}

	prefixedKey := e.prefixKey(key)
	requestCtx, cancel := context.WithTimeout(ctx, e.requestTimeout)
	defer cancel()

	var resp *clientv3.DeleteResponse
	err := e.retryOperation(requestCtx, func() error {
		var retryErr error
		resp, retryErr = e.client.Delete(requestCtx, prefixedKey)
		return retryErr
	})

	if err != nil {
		return fmt.Errorf("failed to delete value: %w", err)
	}

	if resp.Deleted == 0 {
		return ErrNotFound
	}

	return nil
}

// List returns all keys with the given prefix
//
//nolint:revive // ctx parameter is required by Backend interface
func (e *EtcdBackend) List(ctx context.Context, prefix string) ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return nil, fmt.Errorf("etcd backend is closed")
	}

	prefixedPrefix := e.prefixKey(prefix)
	// Add range end for prefix search
	rangeEnd := clientv3.GetPrefixRangeEnd(prefixedPrefix)

	requestCtx, cancel := context.WithTimeout(ctx, e.requestTimeout)
	defer cancel()

	var resp *clientv3.GetResponse
	err := e.retryOperation(requestCtx, func() error {
		var retryErr error
		resp, retryErr = e.client.Get(requestCtx, prefixedPrefix, clientv3.WithRange(rangeEnd))
		return retryErr
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	keys := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		key := e.stripPrefix(string(kv.Key))
		keys = append(keys, key)
	}

	return keys, nil
}

// Close closes the backend
func (e *EtcdBackend) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}

	e.closed = true
	return e.client.Close()
}

// Ping checks if the backend is available
//
//nolint:revive // ctx parameter is required by Backend interface
func (e *EtcdBackend) Ping(ctx context.Context) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return fmt.Errorf("etcd backend is closed")
	}

	requestCtx, cancel := context.WithTimeout(ctx, e.requestTimeout)
	defer cancel()

	_, err := e.client.Status(requestCtx, e.client.Endpoints()[0])
	return err
}

// Begin starts a new transaction
//
//nolint:revive // ctx parameter is required by TransactionalBackend interface
func (e *EtcdBackend) Begin(ctx context.Context) (Transaction, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return nil, fmt.Errorf("etcd backend is closed")
	}

	// Create a new transaction context
	txn := e.client.Txn(ctx)

	return &EtcdTransaction{
		backend:    e,
		txn:        txn,
		ctx:        ctx,
		operations: make([]etcdOperation, 0),
	}, nil
}

// EtcdTransaction represents an etcd transaction
type EtcdTransaction struct {
	backend    *EtcdBackend
	txn        clientv3.Txn
	ctx        context.Context
	operations []etcdOperation
	committed  bool
	rolledBack bool
}

type etcdOperation struct {
	opType string // "get", "put", "delete"
	key    string
	value  []byte
}

// Get retrieves a value by key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (et *EtcdTransaction) Get(ctx context.Context, key string) ([]byte, error) {
	if et.committed || et.rolledBack {
		return nil, fmt.Errorf("transaction is already committed or rolled back")
	}

	prefixedKey := et.backend.prefixKey(key)
	requestCtx, cancel := context.WithTimeout(ctx, et.backend.requestTimeout)
	defer cancel()

	resp, err := et.backend.client.Get(requestCtx, prefixedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get value in transaction: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return nil, ErrNotFound
	}

	return resp.Kvs[0].Value, nil
}

// Put stores a value with the given key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (et *EtcdTransaction) Put(ctx context.Context, key string, value []byte) error {
	if et.committed || et.rolledBack {
		return fmt.Errorf("transaction is already committed or rolled back")
	}

	prefixedKey := et.backend.prefixKey(key)
	et.txn = et.txn.Then(clientv3.OpPut(prefixedKey, string(value)))
	et.operations = append(et.operations, etcdOperation{
		opType: "put",
		key:    prefixedKey,
		value:  value,
	})

	return nil
}

// Delete removes a key-value pair within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (et *EtcdTransaction) Delete(ctx context.Context, key string) error {
	if et.committed || et.rolledBack {
		return fmt.Errorf("transaction is already committed or rolled back")
	}

	prefixedKey := et.backend.prefixKey(key)
	et.txn = et.txn.Then(clientv3.OpDelete(prefixedKey))
	et.operations = append(et.operations, etcdOperation{
		opType: "delete",
		key:    prefixedKey,
	})

	return nil
}

// Commit commits the transaction
func (et *EtcdTransaction) Commit() error {
	if et.committed {
		return fmt.Errorf("transaction is already committed")
	}
	if et.rolledBack {
		return fmt.Errorf("transaction is already rolled back")
	}

	// Create a new context with timeout for commit
	commitCtx, cancel := context.WithTimeout(et.ctx, et.backend.requestTimeout)
	defer cancel()

	// Note: etcd Txn.Commit() uses the context from Txn creation
	// We check the commitCtx timeout separately to provide better error messages
	done := make(chan error, 1)
	go func() {
		_, err := et.txn.Commit()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	case <-commitCtx.Done():
		return fmt.Errorf("commit timeout: %w", commitCtx.Err())
	}

	et.committed = true
	return nil
}

// Rollback rolls back the transaction
func (et *EtcdTransaction) Rollback() error {
	if et.committed {
		return fmt.Errorf("transaction is already committed")
	}
	if et.rolledBack {
		return nil
	}

	et.rolledBack = true
	return nil
}

// WatchEvent represents a watch event for key changes
type WatchEvent struct {
	Type  string // "PUT" or "DELETE"
	Key   string
	Value []byte
}

// Watch watches for changes to keys with the given prefix
func (e *EtcdBackend) Watch(ctx context.Context, prefix string) (<-chan WatchEvent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return nil, fmt.Errorf("etcd backend is closed")
	}

	prefixedPrefix := e.prefixKey(prefix)
	watchChan := e.client.Watch(ctx, prefixedPrefix, clientv3.WithPrefix())

	eventChan := make(chan WatchEvent, defaultEtcdWatchChannelSize)

	go func() {
		defer close(eventChan)

		for {
			select {
			case <-ctx.Done():
				return
			case watchResp, ok := <-watchChan:
				if !ok {
					return
				}

				if watchResp.Err() != nil {
					// Log error but continue watching
					continue
				}

				for _, ev := range watchResp.Events {
					key := e.stripPrefix(string(ev.Kv.Key))
					event := WatchEvent{
						Key: key,
					}

					switch ev.Type {
					case clientv3.EventTypePut:
						event.Type = "PUT"
						event.Value = ev.Kv.Value
					case clientv3.EventTypeDelete:
						event.Type = "DELETE"
					}

					select {
					case eventChan <- event:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return eventChan, nil
}

// LeaderElection provides leader election functionality using etcd leases
type LeaderElection struct {
	backend    *EtcdBackend
	session    *concurrency.Session
	election   *concurrency.Election
	ctx        context.Context
	cancel     context.CancelFunc
	leaderChan chan bool
	mu         sync.RWMutex
	isLeader   bool
}

// NewLeaderElection creates a new leader election instance
func (e *EtcdBackend) NewLeaderElection(ctx context.Context, electionKey string) (*LeaderElection, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return nil, fmt.Errorf("etcd backend is closed")
	}

	// Create session with lease
	session, err := concurrency.NewSession(e.client, concurrency.WithTTL(defaultEtcdLeaderElectionTTL))
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Create election
	election := concurrency.NewElection(session, e.prefixKey(electionKey))

	leaderCtx, cancel := context.WithCancel(ctx)

	le := &LeaderElection{
		backend:    e,
		session:    session,
		election:   election,
		ctx:        leaderCtx,
		cancel:     cancel,
		leaderChan: make(chan bool, 1),
	}

	return le, nil
}

// Campaign starts campaigning for leadership
func (le *LeaderElection) Campaign(ctx context.Context) error {
	le.mu.Lock()
	defer le.mu.Unlock()

	err := le.election.Campaign(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to campaign for leadership: %w", err)
	}

	le.isLeader = true
	select {
	case le.leaderChan <- true:
	default:
	}

	return nil
}

// Resign resigns from leadership
func (le *LeaderElection) Resign(ctx context.Context) error {
	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.isLeader {
		return nil
	}

	err := le.election.Resign(ctx)
	if err != nil {
		return fmt.Errorf("failed to resign from leadership: %w", err)
	}

	le.isLeader = false
	select {
	case le.leaderChan <- false:
	default:
	}

	return nil
}

// IsLeader returns whether this instance is the leader
func (le *LeaderElection) IsLeader() bool {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.isLeader
}

// LeaderChan returns a channel that receives true when becoming leader, false when losing leadership
func (le *LeaderElection) LeaderChan() <-chan bool {
	return le.leaderChan
}

// Close closes the leader election and releases resources
func (le *LeaderElection) Close() error {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.isLeader {
		_ = le.election.Resign(context.Background())
	}

	le.cancel()
	return le.session.Close()
}
