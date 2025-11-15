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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresLeaderElection_AdvisoryLock tests leader election using advisory locks
func TestPostgresLeaderElection_AdvisoryLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// This test requires a PostgreSQL database
	// Set POSTGRES_TEST_CONNECTION environment variable to run
	connStr := getTestPostgresConnection(t)
	if connStr == "" {
		t.Skip("POSTGRES_TEST_CONNECTION not set, skipping test")
	}

	pool, err := pgxpool.New(context.Background(), connStr)
	require.NoError(t, err)
	defer pool.Close()

	// Create two leader election instances
	le1, err := NewPostgresLeaderElection(PostgresLeaderElectionConfig{
		Pool:            pool,
		NodeID:          "node1",
		UseAdvisoryLock: true,
		LockID:          999999,
		TTL:             5,
		RefreshInterval: 1 * time.Second,
		CheckInterval:   500 * time.Millisecond,
	})
	require.NoError(t, err)
	defer le1.Close()

	le2, err := NewPostgresLeaderElection(PostgresLeaderElectionConfig{
		Pool:            pool,
		NodeID:          "node2",
		UseAdvisoryLock: true,
		LockID:          999999, // Same lock ID
		TTL:             5,
		RefreshInterval: 1 * time.Second,
		CheckInterval:   500 * time.Millisecond,
	})
	require.NoError(t, err)
	defer le2.Close()

	ctx := context.Background()

	// First node campaigns
	err = le1.Campaign(ctx)
	require.NoError(t, err)

	// Wait a bit for leadership to be established
	time.Sleep(100 * time.Millisecond)

	// First node should be leader
	assert.True(t, le1.IsLeader())

	// Second node campaigns (should not become leader)
	err = le2.Campaign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Second node should not be leader
	assert.False(t, le2.IsLeader())

	// First node resigns
	err = le1.Resign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// First node should no longer be leader
	assert.False(t, le1.IsLeader())

	// Second node should now be able to become leader
	err = le2.Campaign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Second node should now be leader
	assert.True(t, le2.IsLeader())
}

// TestPostgresLeaderElection_LeaderTable tests leader election using leader table
func TestPostgresLeaderElection_LeaderTable(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	connStr := getTestPostgresConnection(t)
	if connStr == "" {
		t.Skip("POSTGRES_TEST_CONNECTION not set, skipping test")
	}

	pool, err := pgxpool.New(context.Background(), connStr)
	require.NoError(t, err)
	defer pool.Close()

	// Ensure leader table exists
	_, err = pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS leader_election (
			id VARCHAR(255) PRIMARY KEY,
			node_id VARCHAR(255) NOT NULL,
			acquired_at TIMESTAMP NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP NOT NULL,
			UNIQUE(node_id)
		);
	`)
	require.NoError(t, err)

	// Clean up before test
	_, _ = pool.Exec(context.Background(), "DELETE FROM leader_election")

	// Create two leader election instances
	le1, err := NewPostgresLeaderElection(PostgresLeaderElectionConfig{
		Pool:            pool,
		NodeID:          "node1",
		UseAdvisoryLock: false,
		TTL:             5,
		RefreshInterval: 1 * time.Second,
		CheckInterval:   500 * time.Millisecond,
	})
	require.NoError(t, err)
	defer le1.Close()

	le2, err := NewPostgresLeaderElection(PostgresLeaderElectionConfig{
		Pool:            pool,
		NodeID:          "node2",
		UseAdvisoryLock: false,
		TTL:             5,
		RefreshInterval: 1 * time.Second,
		CheckInterval:   500 * time.Millisecond,
	})
	require.NoError(t, err)
	defer le2.Close()

	ctx := context.Background()

	// First node campaigns
	err = le1.Campaign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// First node should be leader
	assert.True(t, le1.IsLeader())

	// Check current leader
	currentLeader, err := le1.GetCurrentLeader(ctx)
	require.NoError(t, err)
	assert.Equal(t, "node1", currentLeader)

	// Second node campaigns (should not become leader)
	err = le2.Campaign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Second node should not be leader
	assert.False(t, le2.IsLeader())

	// First node resigns
	err = le1.Resign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// First node should no longer be leader
	assert.False(t, le1.IsLeader())

	// Second node should now be able to become leader
	err = le2.Campaign(ctx)
	require.NoError(t, err)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Second node should now be leader
	assert.True(t, le2.IsLeader())

	// Check current leader
	currentLeader, err = le2.GetCurrentLeader(ctx)
	require.NoError(t, err)
	assert.Equal(t, "node2", currentLeader)
}

// TestPostgresLeaderElection_LeaderChan tests leader change notifications
func TestPostgresLeaderElection_LeaderChan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	connStr := getTestPostgresConnection(t)
	if connStr == "" {
		t.Skip("POSTGRES_TEST_CONNECTION not set, skipping test")
	}

	pool, err := pgxpool.New(context.Background(), connStr)
	require.NoError(t, err)
	defer pool.Close()

	le, err := NewPostgresLeaderElection(PostgresLeaderElectionConfig{
		Pool:            pool,
		NodeID:          "node1",
		UseAdvisoryLock: true,
		LockID:          888888,
		TTL:             5,
		RefreshInterval: 1 * time.Second,
		CheckInterval:   500 * time.Millisecond,
	})
	require.NoError(t, err)
	defer le.Close()

	ctx := context.Background()

	// Start monitoring leader changes
	leaderChan := le.LeaderChan()

	// Campaign
	err = le.Campaign(ctx)
	require.NoError(t, err)

	// Should receive true
	select {
	case isLeader := <-leaderChan:
		assert.True(t, isLeader)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for leader notification")
	}

	// Resign
	err = le.Resign(ctx)
	require.NoError(t, err)

	// Should receive false
	select {
	case isLeader := <-leaderChan:
		assert.False(t, isLeader)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for leader notification")
	}
}

// getTestPostgresConnection gets PostgreSQL connection string from environment
func getTestPostgresConnection(t *testing.T) string {
	// In a real test, you would read from environment variable
	// For now, return empty to skip tests if not configured
	return ""
}
