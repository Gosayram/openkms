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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const (
	// defaultAuditKeyRotationInterval is the default interval for audit key rotation (90 days)
	defaultAuditKeyRotationInterval = 90 * 24 * time.Hour
)

// Signer provides signing functionality for audit logs
type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	keyCreated time.Time
	mu         sync.RWMutex
}

// SignedEvent represents a signed audit event
type SignedEvent struct {
	Event     *Event    `json:"event"`
	Signature string    `json:"signature"`
	KeyID     string    `json:"key_id"`
	Timestamp time.Time `json:"timestamp"`
}

// BatchSignature represents a signature for a batch of events
type BatchSignature struct {
	Events    []*Event  `json:"events"`
	Signature string    `json:"signature"`
	KeyID     string    `json:"key_id"`
	Timestamp time.Time `json:"timestamp"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// NewSigner creates a new audit log signer with a generated key pair
func NewSigner() (*Signer, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit key pair: %w", err)
	}

	// Generate key ID from public key hash
	keyID := generateKeyID(publicKey)

	return &Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		keyCreated: time.Now().UTC(),
	}, nil
}

// NewSignerFromKey creates a new signer from an existing private key
func NewSignerFromKey(privateKey ed25519.PrivateKey) (*Signer, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type")
	}

	keyID := generateKeyID(publicKey)

	return &Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		keyCreated: time.Now().UTC(),
	}, nil
}

// SignEvent signs a single audit event
func (s *Signer) SignEvent(event *Event) (*SignedEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Serialize event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	// Sign the event
	signature := ed25519.Sign(s.privateKey, eventJSON)

	return &SignedEvent{
		Event:     event,
		Signature: base64.StdEncoding.EncodeToString(signature),
		KeyID:     s.keyID,
		Timestamp: time.Now().UTC(),
	}, nil
}

// SignBatch signs a batch of audit events
func (s *Signer) SignBatch(events []*Event) (*BatchSignature, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("no events to sign")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find time range
	startTime := events[0].Timestamp
	endTime := events[0].Timestamp
	for _, event := range events {
		if event.Timestamp.Before(startTime) {
			startTime = event.Timestamp
		}
		if event.Timestamp.After(endTime) {
			endTime = event.Timestamp
		}
	}

	// Create batch data for signing
	batchData := struct {
		Events    []*Event  `json:"events"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
		Count     int       `json:"count"`
	}{
		Events:    events,
		StartTime: startTime,
		EndTime:   endTime,
		Count:     len(events),
	}

	// Serialize batch to JSON
	batchJSON, err := json.Marshal(batchData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch: %w", err)
	}

	// Sign the batch
	signature := ed25519.Sign(s.privateKey, batchJSON)

	return &BatchSignature{
		Events:    events,
		Signature: base64.StdEncoding.EncodeToString(signature),
		KeyID:     s.keyID,
		Timestamp: time.Now().UTC(),
		StartTime: startTime,
		EndTime:   endTime,
	}, nil
}

// VerifyEvent verifies a signed event
func (s *Signer) VerifyEvent(signedEvent *SignedEvent) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check key ID matches
	if signedEvent.KeyID != s.keyID {
		return fmt.Errorf("key ID mismatch: expected %s, got %s", s.keyID, signedEvent.KeyID)
	}

	// Deserialize signature
	signature, err := base64.StdEncoding.DecodeString(signedEvent.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Serialize event to JSON
	eventJSON, err := json.Marshal(signedEvent.Event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(s.publicKey, eventJSON, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// VerifyBatch verifies a batch signature
func (s *Signer) VerifyBatch(batch *BatchSignature) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check key ID matches
	if batch.KeyID != s.keyID {
		return fmt.Errorf("key ID mismatch: expected %s, got %s", s.keyID, batch.KeyID)
	}

	// Deserialize signature
	signature, err := base64.StdEncoding.DecodeString(batch.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create batch data for verification
	batchData := struct {
		Events    []*Event  `json:"events"`
		StartTime time.Time `json:"start_time"`
		EndTime   time.Time `json:"end_time"`
		Count     int       `json:"count"`
	}{
		Events:    batch.Events,
		StartTime: batch.StartTime,
		EndTime:   batch.EndTime,
		Count:     len(batch.Events),
	}

	// Serialize batch to JSON
	batchJSON, err := json.Marshal(batchData)
	if err != nil {
		return fmt.Errorf("failed to marshal batch: %w", err)
	}

	// Verify signature
	if !ed25519.Verify(s.publicKey, batchJSON, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// GetPublicKey returns the public key for verification
func (s *Signer) GetPublicKey() ed25519.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicKey
}

// GetKeyID returns the key ID
func (s *Signer) GetKeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyID
}

// ShouldRotateKey checks if the key should be rotated
func (s *Signer) ShouldRotateKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.keyCreated) >= defaultAuditKeyRotationInterval
}

// RotateKey generates a new key pair
func (s *Signer) RotateKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate new audit key pair: %w", err)
	}

	keyID := generateKeyID(publicKey)

	s.privateKey = privateKey
	s.publicKey = publicKey
	s.keyID = keyID
	s.keyCreated = time.Now().UTC()

	return nil
}

// generateKeyID generates a key ID from public key
func generateKeyID(publicKey ed25519.PublicKey) string {
	hash := sha256.Sum256(publicKey)
	return base64.StdEncoding.EncodeToString(hash[:])[:16] // Use first 16 bytes
}
