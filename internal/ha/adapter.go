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
	"time"
)

// ServerHealthChecker interface for server health checking
type ServerHealthChecker interface {
	Check(ctx context.Context) (*ServerHealthCheckResult, error)
}

// ServerHealthCheckAdapter adapts HA health checker to server health checker interface
type ServerHealthCheckAdapter struct {
	checker *DefaultHealthChecker
}

// NewServerHealthCheckAdapter creates a new adapter
func NewServerHealthCheckAdapter(checker *DefaultHealthChecker) ServerHealthChecker {
	return &ServerHealthCheckAdapter{
		checker: checker,
	}
}

// ServerHealthCheckResult represents health check result for server
type ServerHealthCheckResult struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Timestamp   string                 `json:"timestamp"`
	Components  map[string]interface{} `json:"components,omitempty"`
	Leader      *ServerLeaderInfo      `json:"leader,omitempty"`
	ReadReplica *ServerReadReplicaInfo `json:"read_replica,omitempty"`
}

// ServerLeaderInfo contains leader election information
type ServerLeaderInfo struct {
	IsLeader bool   `json:"is_leader"`
	NodeID   string `json:"node_id,omitempty"`
}

// ServerReadReplicaInfo contains read replica information
type ServerReadReplicaInfo struct {
	Enabled    bool   `json:"enabled"`
	Available  bool   `json:"available"`
	Connection string `json:"connection,omitempty"`
}

// Check performs health check and adapts result to server format
func (a *ServerHealthCheckAdapter) Check(ctx context.Context) (*ServerHealthCheckResult, error) {
	health, err := a.checker.Check(ctx)
	if err != nil {
		return nil, err
	}

	result := &ServerHealthCheckResult{
		Status:     string(health.Status),
		Message:    health.Message,
		Timestamp:  health.Timestamp.Format(time.RFC3339),
		Components: make(map[string]interface{}),
	}

	// Convert components
	for name, comp := range health.Components {
		result.Components[name] = map[string]interface{}{
			"status":    string(comp.Status),
			"message":   comp.Message,
			"timestamp": comp.Timestamp.Format(time.RFC3339),
		}
	}

	// Convert leader info
	if health.Leader != nil {
		result.Leader = &ServerLeaderInfo{
			IsLeader: health.Leader.IsLeader,
			NodeID:   health.Leader.NodeID,
		}
	}

	// Convert read replica info
	if health.ReadReplica != nil {
		result.ReadReplica = &ServerReadReplicaInfo{
			Enabled:    health.ReadReplica.Enabled,
			Available:  health.ReadReplica.Available,
			Connection: health.ReadReplica.Connection,
		}
	}

	return result, nil
}
