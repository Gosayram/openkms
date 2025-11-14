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

// Package storage provides storage backends including PostgreSQL implementation.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// defaultMaxConns is the default maximum number of connections
	defaultMaxConns = 25
	// defaultMinConns is the default minimum number of connections
	defaultMinConns = 5
	// defaultConnMaxLifetime is the default maximum connection lifetime
	defaultConnMaxLifetime = 5 * time.Minute
	// defaultConnMaxIdleTime is the default maximum idle connection time
	defaultConnMaxIdleTime = 10 * time.Minute
	// defaultPingTimeout is the default timeout for ping operations
	defaultPingTimeout = 5 * time.Second
	// defaultMigrationTimeout is the default timeout for migration operations
	defaultMigrationTimeout = 30 * time.Second
)

// PostgresBackend is a PostgreSQL-based storage backend
type PostgresBackend struct {
	pool *pgxpool.Pool
}

// PostgresConfig holds PostgreSQL connection configuration
type PostgresConfig struct {
	// ConnectionString is the PostgreSQL connection string
	ConnectionString string
	// MaxConns is the maximum number of connections (default: 25)
	MaxConns int32
	// MinConns is the minimum number of connections (default: 5)
	MinConns int32
	// ConnMaxLifetime is the maximum connection lifetime (default: 5m)
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime is the maximum idle connection time (default: 10m)
	ConnMaxIdleTime time.Duration
}

// NewPostgresBackend creates a new PostgreSQL-based storage backend
func NewPostgresBackend(config PostgresConfig) (*PostgresBackend, error) {
	// Parse connection string
	pgxConfig, err := pgxpool.ParseConfig(config.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Configure connection pool
	maxConns := config.MaxConns
	if maxConns == 0 {
		maxConns = defaultMaxConns
	}
	pgxConfig.MaxConns = maxConns

	minConns := config.MinConns
	if minConns == 0 {
		minConns = defaultMinConns
	}
	pgxConfig.MinConns = minConns

	connMaxLifetime := config.ConnMaxLifetime
	if connMaxLifetime == 0 {
		connMaxLifetime = defaultConnMaxLifetime
	}
	pgxConfig.MaxConnLifetime = connMaxLifetime

	connMaxIdleTime := config.ConnMaxIdleTime
	if connMaxIdleTime == 0 {
		connMaxIdleTime = defaultConnMaxIdleTime
	}
	pgxConfig.MaxConnIdleTime = connMaxIdleTime

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), pgxConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), defaultPingTimeout)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Run migrations
	migrator := NewMigrator(pool, GetMigrations())
	migrateCtx, migrateCancel := context.WithTimeout(context.Background(), defaultMigrationTimeout)
	defer migrateCancel()

	if err := migrator.Migrate(migrateCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return &PostgresBackend{
		pool: pool,
	}, nil
}

// Get retrieves a value by key
//
//nolint:revive // ctx parameter is required by Backend interface
func (p *PostgresBackend) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte

	err := p.pool.QueryRow(ctx, "SELECT value FROM storage_data WHERE key = $1", key).Scan(&value)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get value: %w", err)
	}

	return value, nil
}

// Put stores a value with the given key
//
//nolint:revive // ctx parameter is required by Backend interface
func (p *PostgresBackend) Put(ctx context.Context, key string, value []byte) error {
	query := `
		INSERT INTO storage_data (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE
		SET value = EXCLUDED.value, updated_at = NOW()
	`

	_, err := p.pool.Exec(ctx, query, key, value)
	if err != nil {
		return fmt.Errorf("failed to put value: %w", err)
	}

	return nil
}

// Delete removes a key-value pair
//
//nolint:revive // ctx parameter is required by Backend interface
func (p *PostgresBackend) Delete(ctx context.Context, key string) error {
	result, err := p.pool.Exec(ctx, "DELETE FROM storage_data WHERE key = $1", key)
	if err != nil {
		return fmt.Errorf("failed to delete value: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// List returns all keys with the given prefix
//
//nolint:revive // ctx parameter is required by Backend interface
func (p *PostgresBackend) List(ctx context.Context, prefix string) ([]string, error) {
	query := "SELECT key FROM storage_data WHERE key LIKE $1 ORDER BY key"
	rows, err := p.pool.Query(ctx, query, prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
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

// Close closes the backend
func (p *PostgresBackend) Close() error {
	p.pool.Close()
	return nil
}

// Ping checks if the backend is available
//
//nolint:revive // ctx parameter is required by Backend interface
func (p *PostgresBackend) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// Begin starts a new transaction
//
//nolint:revive // ctx parameter is required by TransactionalBackend interface
func (p *PostgresBackend) Begin(ctx context.Context) (Transaction, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &PostgresTransaction{
		tx: tx,
	}, nil
}

// PostgresTransaction represents a PostgreSQL transaction
type PostgresTransaction struct {
	tx pgx.Tx
}

// Get retrieves a value by key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (pt *PostgresTransaction) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte

	err := pt.tx.QueryRow(ctx, "SELECT value FROM storage_data WHERE key = $1", key).Scan(&value)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get value: %w", err)
	}

	return value, nil
}

// Put stores a value with the given key within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (pt *PostgresTransaction) Put(ctx context.Context, key string, value []byte) error {
	query := `
		INSERT INTO storage_data (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE
		SET value = EXCLUDED.value, updated_at = NOW()
	`

	_, err := pt.tx.Exec(ctx, query, key, value)
	if err != nil {
		return fmt.Errorf("failed to put value: %w", err)
	}

	return nil
}

// Delete removes a key-value pair within the transaction
//
//nolint:revive // ctx parameter is required by Transaction interface
func (pt *PostgresTransaction) Delete(ctx context.Context, key string) error {
	result, err := pt.tx.Exec(ctx, "DELETE FROM storage_data WHERE key = $1", key)
	if err != nil {
		return fmt.Errorf("failed to delete value: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Commit commits the transaction
func (pt *PostgresTransaction) Commit() error {
	return pt.tx.Commit(context.Background())
}

// Rollback rolls back the transaction
func (pt *PostgresTransaction) Rollback() error {
	return pt.tx.Rollback(context.Background())
}
