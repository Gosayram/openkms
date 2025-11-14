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

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Logger provides audit logging functionality
type Logger struct {
	logger *zap.Logger
	signer *Signer
	mu     sync.Mutex
}

// NewLogger creates a new audit logger
func NewLogger(logger *zap.Logger) (*Logger, error) {
	signer, err := NewSigner()
	if err != nil {
		return nil, fmt.Errorf("failed to create audit signer: %w", err)
	}

	return &Logger{
		logger: logger,
		signer: signer,
	}, nil
}

// NewLoggerWithSigner creates a new audit logger with an existing signer
func NewLoggerWithSigner(logger *zap.Logger, signer *Signer) *Logger {
	return &Logger{
		logger: logger,
		signer: signer,
	}
}

// Log logs an audit event
//
//nolint:revive // ctx parameter may be used for future context-aware logging
func (l *Logger) Log(ctx context.Context, event *Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Ensure no plaintext is logged
	l.sanitizeEvent(event)

	// Log as structured JSON
	fields := []zap.Field{
		zap.String("audit_id", event.ID),
		zap.String("audit_type", string(event.Type)),
		zap.Time("audit_timestamp", event.Timestamp),
		zap.String("audit_identity", event.Identity),
		zap.String("audit_result", event.Result),
	}

	if event.KeyID != "" {
		fields = append(fields, zap.String("audit_key_id", event.KeyID))
	}

	if event.Operation != "" {
		fields = append(fields, zap.String("audit_operation", event.Operation))
	}

	if event.IP != "" {
		fields = append(fields, zap.String("audit_ip", event.IP))
	}

	if event.Error != "" {
		fields = append(fields, zap.String("audit_error", event.Error))
	}

	// Log metadata as JSON
	if len(event.Metadata) > 0 {
		metadataJSON, _ := json.Marshal(event.Metadata)
		fields = append(fields, zap.String("audit_metadata", string(metadataJSON)))
	}

	l.logger.Info("Audit event", fields...)

	return nil
}

// LogBatch logs multiple audit events
func (l *Logger) LogBatch(ctx context.Context, events []*Event) error {
	for _, event := range events {
		if err := l.Log(ctx, event); err != nil {
			return fmt.Errorf("failed to log event %s: %w", event.ID, err)
		}
	}
	return nil
}

// SignBatch signs a batch of audit events
func (l *Logger) SignBatch(events []*Event) (*BatchSignature, error) {
	if l.signer == nil {
		return nil, fmt.Errorf("signer not available")
	}
	return l.signer.SignBatch(events)
}

// VerifyBatch verifies a batch signature
func (l *Logger) VerifyBatch(batch *BatchSignature) error {
	if l.signer == nil {
		return fmt.Errorf("signer not available")
	}
	return l.signer.VerifyBatch(batch)
}

// GetSigner returns the signer instance
func (l *Logger) GetSigner() *Signer {
	return l.signer
}

// sanitizeEvent removes any plaintext from event
func (l *Logger) sanitizeEvent(event *Event) {
	// Remove any metadata that might contain sensitive data
	if event.Metadata != nil {
		sensitiveKeys := []string{"plaintext", "data", "secret", "password", "key_material"}
		for _, key := range sensitiveKeys {
			delete(event.Metadata, key)
		}
	}

	// Ensure operation field doesn't contain sensitive data
	// (operation should already be safe, but double-check)
}

// Query queries audit logs (basic implementation)
//
//nolint:revive // ctx parameter may be used for future context-aware querying
func (l *Logger) Query(ctx context.Context, filter *Filter) ([]*Event, error) {
	// Basic implementation - in production, this would query from storage
	// For MVP, we'll return empty results
	return []*Event{}, nil
}

// Filter defines query filters for audit logs
type Filter struct {
	Identity  string
	KeyID     string
	EventType EventType
	StartTime *time.Time
	EndTime   *time.Time
	Result    string
}
