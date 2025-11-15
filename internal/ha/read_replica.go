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

package ha

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// defaultReadReplicaMaxConns is the default maximum number of connections for read replica
	defaultReadReplicaMaxConns = 10
	// defaultReadReplicaMinConns is the default minimum number of connections for read replica
	defaultReadReplicaMinConns = 2
	// defaultReadReplicaConnMaxLifetime is the default maximum connection lifetime for read replica
	defaultReadReplicaConnMaxLifetime = 5 * time.Minute
	// defaultReadReplicaConnMaxIdleTime is the default maximum idle connection time for read replica
	defaultReadReplicaConnMaxIdleTime = 10 * time.Minute
	// defaultReadReplicaPingTimeout is the default timeout for ping operations on read replica
	defaultReadReplicaPingTimeout = 5 * time.Second
)

// ReadReplicaBackend provides read-only access to a read replica
type ReadReplicaBackend struct {
	pool *pgxpool.Pool
}

// ReadReplicaConfig holds read replica configuration
type ReadReplicaConfig struct {
	// ConnectionString is the PostgreSQL connection string for the read replica
	ConnectionString string
	// MaxConns is the maximum number of connections (default: 10)
	MaxConns int32
	// MinConns is the minimum number of connections (default: 2)
	MinConns int32
	// ConnMaxLifetime is the maximum connection lifetime (default: 5m)
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime is the maximum idle connection time (default: 10m)
	ConnMaxIdleTime time.Duration
}

// NewReadReplicaBackend creates a new read replica backend
func NewReadReplicaBackend(config ReadReplicaConfig) (*ReadReplicaBackend, error) {
	if config.ConnectionString == "" {
		return nil, fmt.Errorf("connection string is required")
	}

	// Parse connection string
	pgxConfig, err := pgxpool.ParseConfig(config.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Configure connection pool
	maxConns := config.MaxConns
	if maxConns == 0 {
		maxConns = defaultReadReplicaMaxConns
	}
	pgxConfig.MaxConns = maxConns

	minConns := config.MinConns
	if minConns == 0 {
		minConns = defaultReadReplicaMinConns
	}
	pgxConfig.MinConns = minConns

	connMaxLifetime := config.ConnMaxLifetime
	if connMaxLifetime == 0 {
		connMaxLifetime = defaultReadReplicaConnMaxLifetime
	}
	pgxConfig.MaxConnLifetime = connMaxLifetime

	connMaxIdleTime := config.ConnMaxIdleTime
	if connMaxIdleTime == 0 {
		connMaxIdleTime = defaultReadReplicaConnMaxIdleTime
	}
	pgxConfig.MaxConnIdleTime = connMaxIdleTime

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), pgxConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), defaultReadReplicaPingTimeout)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping read replica: %w", err)
	}

	return &ReadReplicaBackend{
		pool: pool,
	}, nil
}

// Get retrieves a value by key from the read replica
func (rr *ReadReplicaBackend) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte

	err := rr.pool.QueryRow(ctx, "SELECT value FROM storage_data WHERE key = $1", key).Scan(&value)
	if err != nil {
		return nil, fmt.Errorf("failed to get value from read replica: %w", err)
	}

	return value, nil
}

// List returns all keys with the given prefix from the read replica
func (rr *ReadReplicaBackend) List(ctx context.Context, prefix string) ([]string, error) {
	query := "SELECT key FROM storage_data WHERE key LIKE $1 ORDER BY key"
	rows, err := rr.pool.Query(ctx, query, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from read replica: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}
		keys = append(keys, key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return keys, nil
}

// Ping checks if the read replica is available
func (rr *ReadReplicaBackend) Ping(ctx context.Context) error {
	return rr.pool.Ping(ctx)
}

// Close closes the read replica backend
func (rr *ReadReplicaBackend) Close() error {
	rr.pool.Close()
	return nil
}
