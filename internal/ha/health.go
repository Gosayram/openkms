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
	"encoding/json"
	"fmt"
	"time"
)

const (
	// defaultHealthCheckTimeout is the default timeout for health checks
	defaultHealthCheckTimeout = 5 * time.Second
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	// HealthStatusHealthy indicates the component is healthy
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusUnhealthy indicates the component is unhealthy
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	// HealthStatusDegraded indicates the component is degraded but functional
	HealthStatusDegraded HealthStatus = "degraded"
)

// HealthCheck represents a health check result
type HealthCheck struct {
	Status      HealthStatus         `json:"status"`
	Message     string               `json:"message,omitempty"`
	Timestamp   time.Time            `json:"timestamp"`
	Components  map[string]Component `json:"components,omitempty"`
	Leader      *LeaderInfo          `json:"leader,omitempty"`
	ReadReplica *ReadReplicaInfo     `json:"read_replica,omitempty"`
}

// Component represents a component health check
type Component struct {
	Status    HealthStatus `json:"status"`
	Message   string       `json:"message,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// LeaderInfo contains leader election information
type LeaderInfo struct {
	IsLeader bool   `json:"is_leader"`
	NodeID   string `json:"node_id,omitempty"`
}

// ReadReplicaInfo contains read replica information
type ReadReplicaInfo struct {
	Enabled    bool   `json:"enabled"`
	Available  bool   `json:"available"`
	Connection string `json:"connection,omitempty"`
}

// HealthChecker provides health check functionality
type HealthChecker interface {
	// Check performs a health check
	Check(ctx context.Context) (*HealthCheck, error)
}

// DefaultHealthChecker implements a default health checker
type DefaultHealthChecker struct {
	storageChecker    StorageHealthChecker
	leaderElection    LeaderElection
	nodeID            string
	readReplicaStatus *ReadReplicaStatus
}

// StorageHealthChecker checks storage health
type StorageHealthChecker interface {
	Ping(ctx context.Context) error
}

// ReadReplicaStatus represents read replica status
type ReadReplicaStatus struct {
	Enabled    bool
	Available  bool
	Connection string
	Checker    StorageHealthChecker
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(
	storageChecker StorageHealthChecker,
	leaderElection LeaderElection,
	nodeID string,
	readReplicaStatus *ReadReplicaStatus,
) *DefaultHealthChecker {
	return &DefaultHealthChecker{
		storageChecker:    storageChecker,
		leaderElection:    leaderElection,
		nodeID:            nodeID,
		readReplicaStatus: readReplicaStatus,
	}
}

// Check performs a comprehensive health check
func (hc *DefaultHealthChecker) Check(ctx context.Context) (*HealthCheck, error) {
	checkCtx, cancel := context.WithTimeout(ctx, defaultHealthCheckTimeout)
	defer cancel()

	health := &HealthCheck{
		Status:     HealthStatusHealthy,
		Timestamp:  time.Now(),
		Components: make(map[string]Component),
	}

	// Check storage
	storageStatus := hc.checkStorage(checkCtx)
	health.Components["storage"] = storageStatus
	if storageStatus.Status != HealthStatusHealthy {
		health.Status = HealthStatusUnhealthy
		health.Message = "storage is unhealthy"
	}

	// Check leader election
	if hc.leaderElection != nil {
		leaderInfo := &LeaderInfo{
			IsLeader: hc.leaderElection.IsLeader(),
			NodeID:   hc.nodeID,
		}
		health.Leader = leaderInfo

		leaderComponent := Component{
			Status:    HealthStatusHealthy,
			Timestamp: time.Now(),
		}
		if !leaderInfo.IsLeader {
			leaderComponent.Status = HealthStatusDegraded
			leaderComponent.Message = "not the leader"
			if health.Status == HealthStatusHealthy {
				health.Status = HealthStatusDegraded
			}
		}
		health.Components["leader_election"] = leaderComponent
	}

	// Check read replica
	if hc.readReplicaStatus != nil {
		readReplicaInfo := &ReadReplicaInfo{
			Enabled:    hc.readReplicaStatus.Enabled,
			Available:  hc.readReplicaStatus.Available,
			Connection: hc.readReplicaStatus.Connection,
		}

		if hc.readReplicaStatus.Enabled {
			replicaStatus := hc.checkReadReplica(checkCtx)
			health.Components["read_replica"] = replicaStatus
			readReplicaInfo.Available = replicaStatus.Status == HealthStatusHealthy

			if replicaStatus.Status == HealthStatusUnhealthy {
				// Read replica failure is not critical, but degrades health
				if health.Status == HealthStatusHealthy {
					health.Status = HealthStatusDegraded
					if health.Message == "" {
						health.Message = "read replica is unavailable"
					}
				}
			}
		}

		health.ReadReplica = readReplicaInfo
	}

	return health, nil
}

// checkStorage checks storage health
func (hc *DefaultHealthChecker) checkStorage(ctx context.Context) Component {
	if hc.storageChecker == nil {
		return Component{
			Status:    HealthStatusUnhealthy,
			Message:   "storage checker not configured",
			Timestamp: time.Now(),
		}
	}

	err := hc.storageChecker.Ping(ctx)
	if err != nil {
		return Component{
			Status:    HealthStatusUnhealthy,
			Message:   fmt.Sprintf("storage ping failed: %v", err),
			Timestamp: time.Now(),
		}
	}

	return Component{
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
	}
}

// checkReadReplica checks read replica health
func (hc *DefaultHealthChecker) checkReadReplica(ctx context.Context) Component {
	if hc.readReplicaStatus == nil || !hc.readReplicaStatus.Enabled {
		return Component{
			Status:    HealthStatusUnhealthy,
			Message:   "read replica not configured",
			Timestamp: time.Now(),
		}
	}

	if hc.readReplicaStatus.Checker == nil {
		return Component{
			Status:    HealthStatusUnhealthy,
			Message:   "read replica checker not configured",
			Timestamp: time.Now(),
		}
	}

	err := hc.readReplicaStatus.Checker.Ping(ctx)
	if err != nil {
		return Component{
			Status:    HealthStatusDegraded,
			Message:   fmt.Sprintf("read replica ping failed: %v", err),
			Timestamp: time.Now(),
		}
	}

	return Component{
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
	}
}

// ToJSON converts health check to JSON
func (hc *HealthCheck) ToJSON() ([]byte, error) {
	return json.Marshal(hc)
}
