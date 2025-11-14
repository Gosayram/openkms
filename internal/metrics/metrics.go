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

// Package metrics provides Prometheus metrics for OpenKMS.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// OperationDuration tracks the duration of operations in seconds
	OperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "openkms_operation_duration_seconds",
			Help:    "Duration of operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation", "status"},
	)

	// OperationTotal tracks the total number of operations
	OperationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openkms_operations_total",
			Help: "Total number of operations",
		},
		[]string{"operation", "status"},
	)

	// KeyUsageCounter tracks key usage by key ID and operation type
	KeyUsageCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openkms_key_usage_total",
			Help: "Total number of key usages",
		},
		[]string{"key_id", "operation"},
	)

	// ErrorRate tracks error rate by operation type
	ErrorRate = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openkms_errors_total",
			Help: "Total number of errors",
		},
		[]string{"operation", "error_type"},
	)

	// ActiveKeys tracks the number of active keys
	ActiveKeys = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "openkms_active_keys",
			Help: "Number of active keys",
		},
	)

	// KeyRotations tracks the number of key rotations
	KeyRotations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openkms_key_rotations_total",
			Help: "Total number of key rotations",
		},
		[]string{"key_id"},
	)
)

// RecordOperation records an operation with duration and status
func RecordOperation(operation, status string, duration float64) {
	OperationDuration.WithLabelValues(operation, status).Observe(duration)
	OperationTotal.WithLabelValues(operation, status).Inc()
}

// RecordKeyUsage records key usage
func RecordKeyUsage(keyID, operation string) {
	KeyUsageCounter.WithLabelValues(keyID, operation).Inc()
}

// RecordError records an error
func RecordError(operation, errorType string) {
	ErrorRate.WithLabelValues(operation, errorType).Inc()
}

// SetActiveKeys sets the number of active keys
func SetActiveKeys(count float64) {
	ActiveKeys.Set(count)
}

// RecordKeyRotation records a key rotation
func RecordKeyRotation(keyID string) {
	KeyRotations.WithLabelValues(keyID).Inc()
}
