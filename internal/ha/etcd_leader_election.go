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
	"sync"

	"github.com/Gosayram/openkms/internal/storage"
)

// EtcdLeaderElectionAdapter adapts etcd leader election to the LeaderElection interface
type EtcdLeaderElectionAdapter struct {
	le         *storage.LeaderElection
	mu         sync.RWMutex
	isLeader   bool
	leaderChan chan bool
}

// NewEtcdLeaderElectionAdapter creates a new adapter for etcd leader election
func NewEtcdLeaderElectionAdapter(
	backend *storage.EtcdBackend,
	electionKey string,
) (*EtcdLeaderElectionAdapter, error) {
	ctx := context.Background()
	le, err := backend.NewLeaderElection(ctx, electionKey)
	if err != nil {
		return nil, err
	}

	adapter := &EtcdLeaderElectionAdapter{
		le:         le,
		leaderChan: make(chan bool, 1),
	}

	// Monitor leader changes
	go adapter.monitorLeaderChanges()

	return adapter, nil
}

// monitorLeaderChanges monitors leader changes from etcd
func (a *EtcdLeaderElectionAdapter) monitorLeaderChanges() {
	for isLeader := range a.le.LeaderChan() {
		a.mu.Lock()
		a.isLeader = isLeader
		a.mu.Unlock()

		select {
		case a.leaderChan <- isLeader:
		default:
		}
	}
}

// Campaign starts campaigning for leadership
func (a *EtcdLeaderElectionAdapter) Campaign(ctx context.Context) error {
	return a.le.Campaign(ctx)
}

// Resign resigns from leadership
func (a *EtcdLeaderElectionAdapter) Resign(ctx context.Context) error {
	return a.le.Resign(ctx)
}

// IsLeader returns whether this instance is the leader
func (a *EtcdLeaderElectionAdapter) IsLeader() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isLeader
}

// LeaderChan returns a channel that receives true when becoming leader, false when losing leadership
func (a *EtcdLeaderElectionAdapter) LeaderChan() <-chan bool {
	return a.leaderChan
}

// Close closes the leader election and releases resources
func (a *EtcdLeaderElectionAdapter) Close() error {
	return a.le.Close()
}
