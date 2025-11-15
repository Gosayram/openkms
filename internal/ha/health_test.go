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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockStorageChecker is a mock storage health checker
type mockStorageChecker struct {
	pingError error
}

func (m *mockStorageChecker) Ping(ctx context.Context) error {
	return m.pingError
}

// mockLeaderElection is a mock leader election
type mockLeaderElection struct {
	isLeader bool
}

func (m *mockLeaderElection) Campaign(ctx context.Context) error {
	return nil
}

func (m *mockLeaderElection) Resign(ctx context.Context) error {
	return nil
}

func (m *mockLeaderElection) IsLeader() bool {
	return m.isLeader
}

func (m *mockLeaderElection) LeaderChan() <-chan bool {
	return make(chan bool)
}

func (m *mockLeaderElection) Close() error {
	return nil
}

// TestDefaultHealthChecker_Check tests health checker
func TestDefaultHealthChecker_Check(t *testing.T) {
	tests := []struct {
		name              string
		storageError      error
		isLeader          bool
		readReplicaStatus *ReadReplicaStatus
		expectedStatus    HealthStatus
	}{
		{
			name:           "healthy with leader",
			storageError:   nil,
			isLeader:       true,
			expectedStatus: HealthStatusHealthy,
		},
		{
			name:           "degraded without leader",
			storageError:   nil,
			isLeader:       false,
			expectedStatus: HealthStatusDegraded,
		},
		{
			name:           "unhealthy storage",
			storageError:   errors.New("storage error"),
			isLeader:       true,
			expectedStatus: HealthStatusUnhealthy,
		},
		{
			name:         "degraded with read replica unavailable",
			storageError: nil,
			isLeader:     false,
			readReplicaStatus: &ReadReplicaStatus{
				Enabled:   true,
				Available: false,
				Checker:   &mockStorageChecker{pingError: errors.New("replica error")},
			},
			expectedStatus: HealthStatusDegraded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageChecker := &mockStorageChecker{pingError: tt.storageError}
			leaderElection := &mockLeaderElection{isLeader: tt.isLeader}

			checker := NewHealthChecker(
				storageChecker,
				leaderElection,
				"node1",
				tt.readReplicaStatus,
			)

			ctx := context.Background()
			health, err := checker.Check(ctx)

			assert.NoError(t, err)
			assert.NotNil(t, health)
			assert.Equal(t, tt.expectedStatus, health.Status)

			// Check components
			assert.Contains(t, health.Components, "storage")
			assert.Contains(t, health.Components, "leader_election")
			if tt.readReplicaStatus != nil && tt.readReplicaStatus.Enabled {
				assert.Contains(t, health.Components, "read_replica")
			}

			// Check leader info
			assert.NotNil(t, health.Leader)
			assert.Equal(t, tt.isLeader, health.Leader.IsLeader)
			assert.Equal(t, "node1", health.Leader.NodeID)
		})
	}
}

// TestDefaultHealthChecker_Check_StorageError tests storage error handling
func TestDefaultHealthChecker_Check_StorageError(t *testing.T) {
	storageChecker := &mockStorageChecker{pingError: errors.New("connection failed")}
	checker := NewHealthChecker(storageChecker, nil, "node1", nil)

	ctx := context.Background()
	health, err := checker.Check(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, health)
	assert.Equal(t, HealthStatusUnhealthy, health.Status)
	assert.Equal(t, "storage is unhealthy", health.Message)

	storageComp := health.Components["storage"]
	assert.Equal(t, HealthStatusUnhealthy, storageComp.Status)
	assert.Contains(t, storageComp.Message, "storage ping failed")
}

// TestDefaultHealthChecker_Check_ReadReplica tests read replica health check
func TestDefaultHealthChecker_Check_ReadReplica(t *testing.T) {
	storageChecker := &mockStorageChecker{pingError: nil}
	readReplicaStatus := &ReadReplicaStatus{
		Enabled:    true,
		Available:  true,
		Connection: "postgres://replica:5432/db",
		Checker:    &mockStorageChecker{pingError: nil},
	}

	checker := NewHealthChecker(storageChecker, nil, "node1", readReplicaStatus)

	ctx := context.Background()
	health, err := checker.Check(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, health)
	assert.Equal(t, HealthStatusHealthy, health.Status)

	assert.NotNil(t, health.ReadReplica)
	assert.True(t, health.ReadReplica.Enabled)
	assert.True(t, health.ReadReplica.Available)

	replicaComp := health.Components["read_replica"]
	assert.Equal(t, HealthStatusHealthy, replicaComp.Status)
}

// TestHealthCheck_ToJSON tests JSON serialization
func TestHealthCheck_ToJSON(t *testing.T) {
	health := &HealthCheck{
		Status:    HealthStatusHealthy,
		Message:   "All systems operational",
		Timestamp: time.Now(),
		Components: map[string]Component{
			"storage": {
				Status:    HealthStatusHealthy,
				Timestamp: time.Now(),
			},
		},
		Leader: &LeaderInfo{
			IsLeader: true,
			NodeID:   "node1",
		},
	}

	jsonData, err := health.ToJSON()
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)
	assert.Contains(t, string(jsonData), "healthy")
	assert.Contains(t, string(jsonData), "node1")
}
