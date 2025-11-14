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

// GetMigrations returns the list of all database migrations
func GetMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
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
		// Future migrations can be added here
		// {
		// 	Version:     2,
		// 	Description: "Add index for faster lookups",
		// 	Up: func(tx pgx.Tx) error {
		//nolint:lll // SQL statement is necessarily long
		// 		_, err := tx.Exec(context.Background(),
		// 			"CREATE INDEX IF NOT EXISTS idx_storage_data_updated_at ON storage_data(updated_at)")
		// 		return err
		// 	},
		// 	Down: func(tx pgx.Tx) error {
		// 		_, err := tx.Exec(context.Background(), "DROP INDEX IF EXISTS idx_storage_data_updated_at")
		// 		return err
		// 	},
		// },
	}
}
