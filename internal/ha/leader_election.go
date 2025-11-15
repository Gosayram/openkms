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

// Package ha provides high availability features including leader election and health checks.
package ha

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// defaultLeaderLockID is the default PostgreSQL advisory lock ID for leader election
	defaultLeaderLockID = 123456789
	// defaultLeaderTTL is the default TTL for leader lease (in seconds)
	defaultLeaderTTL = 30
	// defaultLeaderRefreshInterval is the default interval for refreshing leader lease
	defaultLeaderRefreshInterval = 10 * time.Second
	// defaultLeaderCheckInterval is the default interval for checking leader status
	defaultLeaderCheckInterval = 5 * time.Second
	// defaultLeaderTimeout is the default timeout for leader operations
	defaultLeaderTimeout = 5 * time.Second
)

var (
	// ErrNotLeader is returned when an operation requires leadership but the instance is not the leader
	ErrNotLeader = errors.New("not the leader")
	// ErrLeaderElectionClosed is returned when leader election is closed
	ErrLeaderElectionClosed = errors.New("leader election is closed")
)

// LeaderElection provides leader election functionality
type LeaderElection interface {
	// Campaign starts campaigning for leadership
	Campaign(ctx context.Context) error
	// Resign resigns from leadership
	Resign(ctx context.Context) error
	// IsLeader returns whether this instance is the leader
	IsLeader() bool
	// LeaderChan returns a channel that receives true when becoming leader, false when losing leadership
	LeaderChan() <-chan bool
	// Close closes the leader election and releases resources
	Close() error
}

// PostgresLeaderElection implements leader election using PostgreSQL advisory locks or leader table
type PostgresLeaderElection struct {
	pool            *pgxpool.Pool
	nodeID          string
	lockID          int64
	useAdvisoryLock bool
	ttl             int
	refreshInterval time.Duration
	checkInterval   time.Duration
	mu              sync.RWMutex
	isLeader        bool
	leaderChan      chan bool
	ctx             context.Context
	cancel          context.CancelFunc
	stopRefresh     chan struct{}
	refreshWg       sync.WaitGroup
	closed          bool
}

// PostgresLeaderElectionConfig holds configuration for PostgreSQL leader election
type PostgresLeaderElectionConfig struct {
	Pool            *pgxpool.Pool
	NodeID          string
	LockID          int64
	UseAdvisoryLock bool // If true, use advisory locks; if false, use leader table
	TTL             int  // TTL in seconds (only used with leader table)
	RefreshInterval time.Duration
	CheckInterval   time.Duration
}

// NewPostgresLeaderElection creates a new PostgreSQL leader election instance
func NewPostgresLeaderElection(config PostgresLeaderElectionConfig) (*PostgresLeaderElection, error) {
	if config.Pool == nil {
		return nil, fmt.Errorf("pool is required")
	}
	if config.NodeID == "" {
		return nil, fmt.Errorf("node ID is required")
	}

	lockID := config.LockID
	if lockID == 0 {
		lockID = defaultLeaderLockID
	}

	ttl := config.TTL
	if ttl == 0 {
		ttl = defaultLeaderTTL
	}

	refreshInterval := config.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultLeaderRefreshInterval
	}

	checkInterval := config.CheckInterval
	if checkInterval == 0 {
		checkInterval = defaultLeaderCheckInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	le := &PostgresLeaderElection{
		pool:            config.Pool,
		nodeID:          config.NodeID,
		lockID:          lockID,
		useAdvisoryLock: config.UseAdvisoryLock,
		ttl:             ttl,
		refreshInterval: refreshInterval,
		checkInterval:   checkInterval,
		leaderChan:      make(chan bool, 1),
		ctx:             ctx,
		cancel:          cancel,
		stopRefresh:     make(chan struct{}),
	}

	// Initialize leader table if not using advisory locks
	if !config.UseAdvisoryLock {
		if err := le.ensureLeaderTable(ctx); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to ensure leader table: %w", err)
		}
	}

	return le, nil
}

// ensureLeaderTable ensures the leader table exists
func (le *PostgresLeaderElection) ensureLeaderTable(ctx context.Context) error {
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

	_, err := le.pool.Exec(ctx, createTableSQL)
	return err
}

// Campaign starts campaigning for leadership
func (le *PostgresLeaderElection) Campaign(ctx context.Context) error {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.closed {
		return ErrLeaderElectionClosed
	}

	if le.useAdvisoryLock {
		return le.campaignWithAdvisoryLock(ctx)
	}

	return le.campaignWithLeaderTable(ctx)
}

// campaignWithAdvisoryLock campaigns using PostgreSQL advisory locks
func (le *PostgresLeaderElection) campaignWithAdvisoryLock(ctx context.Context) error {
	// Try to acquire advisory lock (non-blocking)
	var acquired bool
	err := le.pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", le.lockID).Scan(&acquired)
	if err != nil {
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}

	if !acquired {
		// Lock is held by another node
		le.isLeader = false
		return nil
	}

	le.isLeader = true
	select {
	case le.leaderChan <- true:
	default:
	}

	// Start refresh goroutine
	le.refreshWg.Add(1)
	go le.refreshAdvisoryLock()

	return nil
}

// campaignWithLeaderTable campaigns using leader table
func (le *PostgresLeaderElection) campaignWithLeaderTable(ctx context.Context) error {
	now := time.Now()
	expiresAt := now.Add(time.Duration(le.ttl) * time.Second)

	// Try to acquire leadership
	query := `
		INSERT INTO leader_election (id, node_id, acquired_at, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE
		SET node_id = $2,
		    acquired_at = $3,
		    expires_at = $4
		WHERE leader_election.expires_at < $3 OR leader_election.node_id = $2
	`

	result, err := le.pool.Exec(ctx, query, "leader", le.nodeID, now, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to acquire leadership: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		// Check if we're already the leader
		var currentLeader string
		err := le.pool.QueryRow(ctx,
			"SELECT node_id FROM leader_election WHERE id = 'leader' AND expires_at > NOW()",
		).Scan(&currentLeader)
		if err == nil && currentLeader == le.nodeID {
			le.isLeader = true
			select {
			case le.leaderChan <- true:
			default:
			}
			// Start refresh goroutine
			le.refreshWg.Add(1)
			go le.refreshLeaderTable()
			return nil
		}

		le.isLeader = false
		return nil
	}

	le.isLeader = true
	select {
	case le.leaderChan <- true:
	default:
	}

	// Start refresh goroutine
	le.refreshWg.Add(1)
	go le.refreshLeaderTable()

	return nil
}

// refreshAdvisoryLock refreshes the advisory lock periodically
func (le *PostgresLeaderElection) refreshAdvisoryLock() {
	defer le.refreshWg.Done()

	ticker := time.NewTicker(le.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-le.ctx.Done():
			return
		case <-le.stopRefresh:
			return
		case <-ticker.C:
			le.mu.RLock()
			if !le.isLeader || le.closed {
				le.mu.RUnlock()
				return
			}
			le.mu.RUnlock()

			// Check if we still hold the lock
			var locked bool
			ctx, cancel := context.WithTimeout(context.Background(), defaultLeaderTimeout)
			err := le.pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", le.lockID).Scan(&locked)
			cancel()

			if err != nil || !locked {
				// Lost leadership
				le.mu.Lock()
				le.isLeader = false
				le.mu.Unlock()
				select {
				case le.leaderChan <- false:
				default:
				}
				return
			}
		}
	}
}

// refreshLeaderTable refreshes the leader table entry periodically
func (le *PostgresLeaderElection) refreshLeaderTable() {
	defer le.refreshWg.Done()

	ticker := time.NewTicker(le.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-le.ctx.Done():
			return
		case <-le.stopRefresh:
			return
		case <-ticker.C:
			le.mu.RLock()
			if !le.isLeader || le.closed {
				le.mu.RUnlock()
				return
			}
			le.mu.RUnlock()

			// Refresh the leader entry
			now := time.Now()
			expiresAt := now.Add(time.Duration(le.ttl) * time.Second)

			ctx, cancel := context.WithTimeout(context.Background(), defaultLeaderTimeout)
			result, err := le.pool.Exec(ctx,
				"UPDATE leader_election SET expires_at = $1 WHERE id = 'leader' AND node_id = $2",
				expiresAt, le.nodeID,
			)
			cancel()

			if err != nil {
				// Lost leadership
				le.mu.Lock()
				le.isLeader = false
				le.mu.Unlock()
				select {
				case le.leaderChan <- false:
				default:
				}
				return
			}

			if result.RowsAffected() == 0 {
				// Lost leadership
				le.mu.Lock()
				le.isLeader = false
				le.mu.Unlock()
				select {
				case le.leaderChan <- false:
				default:
				}
				return
			}
		}
	}
}

// Resign resigns from leadership
func (le *PostgresLeaderElection) Resign(ctx context.Context) error {
	le.mu.Lock()
	defer le.mu.Unlock()

	if !le.isLeader {
		return nil
	}

	close(le.stopRefresh)
	le.refreshWg.Wait()
	le.stopRefresh = make(chan struct{})

	if le.useAdvisoryLock {
		_, err := le.pool.Exec(ctx, "SELECT pg_advisory_unlock($1)", le.lockID)
		if err != nil {
			return fmt.Errorf("failed to release advisory lock: %w", err)
		}
	} else {
		_, err := le.pool.Exec(ctx, "DELETE FROM leader_election WHERE id = 'leader' AND node_id = $1", le.nodeID)
		if err != nil {
			return fmt.Errorf("failed to release leadership: %w", err)
		}
	}

	le.isLeader = false
	select {
	case le.leaderChan <- false:
	default:
	}

	return nil
}

// IsLeader returns whether this instance is the leader
func (le *PostgresLeaderElection) IsLeader() bool {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.isLeader
}

// LeaderChan returns a channel that receives true when becoming leader, false when losing leadership
func (le *PostgresLeaderElection) LeaderChan() <-chan bool {
	return le.leaderChan
}

// Close closes the leader election and releases resources
func (le *PostgresLeaderElection) Close() error {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.closed {
		return nil
	}

	le.closed = true
	le.cancel()

	if le.isLeader {
		close(le.stopRefresh)
		le.refreshWg.Wait()

		ctx, cancel := context.WithTimeout(context.Background(), defaultLeaderTimeout)
		defer cancel()

		if le.useAdvisoryLock {
			_, _ = le.pool.Exec(ctx, "SELECT pg_advisory_unlock($1)", le.lockID)
		} else {
			_, _ = le.pool.Exec(ctx, "DELETE FROM leader_election WHERE id = 'leader' AND node_id = $1", le.nodeID)
		}

		le.isLeader = false
	}

	return nil
}

// GetCurrentLeader returns the current leader node ID (for leader table mode)
func (le *PostgresLeaderElection) GetCurrentLeader(ctx context.Context) (string, error) {
	if le.useAdvisoryLock {
		// Advisory locks don't provide leader identity
		return "", fmt.Errorf("advisory lock mode does not provide leader identity")
	}

	var nodeID sql.NullString
	err := le.pool.QueryRow(ctx,
		"SELECT node_id FROM leader_election WHERE id = 'leader' AND expires_at > NOW()",
	).Scan(&nodeID)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("failed to get current leader: %w", err)
	}

	if !nodeID.Valid {
		return "", nil
	}

	return nodeID.String, nil
}
