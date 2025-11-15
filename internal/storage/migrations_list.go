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

	"github.com/jackc/pgx/v5"
)

const (
	// migrationVersion1 is the version number for the initial schema migration
	migrationVersion1 = 1
	// migrationVersion2 is the version number for the leader election table migration
	migrationVersion2 = 2
)

// GetMigrations returns the list of all database migrations
func GetMigrations() []Migration {
	return []Migration{
		{
			Version:     migrationVersion1,
			Description: "Initial schema - create storage_data table",
			Up: func(tx pgx.Tx) error {
				createTableSQL := `
					CREATE TABLE IF NOT EXISTS storage_data (
						key VARCHAR(255) PRIMARY KEY,
						value BYTEA NOT NULL,
						created_at TIMESTAMP NOT NULL DEFAULT NOW(),
						updated_at TIMESTAMP NOT NULL DEFAULT NOW()
					);

					CREATE INDEX IF NOT EXISTS idx_storage_data_key ON storage_data(key);
				`
				_, err := tx.Exec(context.Background(), createTableSQL)
				return err
			},
			Down: func(tx pgx.Tx) error {
				_, err := tx.Exec(context.Background(), "DROP TABLE IF EXISTS storage_data")
				return err
			},
		},
		{
			Version:     migrationVersion2,
			Description: "Create leader_election table for HA",
			Up: func(tx pgx.Tx) error {
				createTableSQL := `
					CREATE TABLE IF NOT EXISTS leader_election (
						id VARCHAR(255) PRIMARY KEY,
						node_id VARCHAR(255) NOT NULL,
						acquired_at TIMESTAMP NOT NULL DEFAULT NOW(),
						expires_at TIMESTAMP NOT NULL,
						UNIQUE(node_id)
					);
					
					CREATE INDEX IF NOT EXISTS idx_leader_election_expires_at ON leader_election(expires_at);
				`
				_, err := tx.Exec(context.Background(), createTableSQL)
				return err
			},
			Down: func(tx pgx.Tx) error {
				_, err := tx.Exec(context.Background(), "DROP TABLE IF EXISTS leader_election")
				return err
			},
		},
	}
}
