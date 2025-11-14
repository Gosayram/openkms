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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// migrationsTableName is the name of the migrations tracking table
	migrationsTableName = "schema_migrations"
)

// Migration represents a database migration
type Migration struct {
	Version     int
	Description string
	Up          func(pgx.Tx) error
	Down        func(pgx.Tx) error
}

// Migrator manages database migrations
type Migrator struct {
	pool       *pgxpool.Pool
	migrations []Migration
}

// NewMigrator creates a new migrator
func NewMigrator(pool *pgxpool.Pool, migrations []Migration) *Migrator {
	return &Migrator{
		pool:       pool,
		migrations: migrations,
	}
}

// ensureMigrationsTable ensures the migrations tracking table exists
func (m *Migrator) ensureMigrationsTable(ctx context.Context) error {
	createTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			version INTEGER PRIMARY KEY,
			description VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`, migrationsTableName)

	_, err := m.pool.Exec(ctx, createTableSQL)
	return err
}

// GetCurrentVersion returns the current schema version
func (m *Migrator) GetCurrentVersion(ctx context.Context) (int, error) {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return 0, fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	var version *int
	err := m.pool.QueryRow(ctx,
		fmt.Sprintf("SELECT MAX(version) FROM %s", migrationsTableName),
	).Scan(&version)

	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}

	if version == nil {
		return 0, nil
	}

	return *version, nil
}

// Migrate applies all pending migrations
func (m *Migrator) Migrate(ctx context.Context) error {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	currentVersion, err := m.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Apply pending migrations
	for _, migration := range m.migrations {
		if migration.Version <= currentVersion {
			continue
		}

		if err := m.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}

	return nil
}

// applyMigration applies a single migration
func (m *Migrator) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && rollbackErr != pgx.ErrTxClosed {
			_ = rollbackErr // Ignore rollback errors after commit
		}
	}()

	// Apply migration
	if err = migration.Up(tx); err != nil {
		return fmt.Errorf("migration up failed: %w", err)
	}

	// Record migration
	insertSQL := fmt.Sprintf(`
		INSERT INTO %s (version, description, applied_at)
		VALUES ($1, $2, $3)
	`, migrationsTableName)

	_, err = tx.Exec(ctx, insertSQL, migration.Version, migration.Description, time.Now())
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	return nil
}

// Rollback rolls back the last migration
func (m *Migrator) Rollback(ctx context.Context) error {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	currentVersion, err := m.GetCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if currentVersion == 0 {
		return fmt.Errorf("no migrations to rollback")
	}

	// Find the migration to rollback
	var migrationToRollback *Migration
	for i := len(m.migrations) - 1; i >= 0; i-- {
		if m.migrations[i].Version == currentVersion {
			migrationToRollback = &m.migrations[i]
			break
		}
	}

	if migrationToRollback == nil {
		return fmt.Errorf("migration version %d not found", currentVersion)
	}

	if migrationToRollback.Down == nil {
		return fmt.Errorf("migration %d does not support rollback", currentVersion)
	}

	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && rollbackErr != pgx.ErrTxClosed {
			_ = rollbackErr // Ignore rollback errors after commit
		}
	}()

	// Rollback migration
	if err = migrationToRollback.Down(tx); err != nil {
		return fmt.Errorf("migration down failed: %w", err)
	}

	// Remove migration record
	deleteSQL := fmt.Sprintf("DELETE FROM %s WHERE version = $1", migrationsTableName)
	_, err = tx.Exec(ctx, deleteSQL, currentVersion)
	if err != nil {
		return fmt.Errorf("failed to remove migration record: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit rollback: %w", err)
	}

	return nil
}

// GetMigrations returns all registered migrations
func (m *Migrator) GetMigrations() []Migration {
	return m.migrations
}
