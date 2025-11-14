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

// Package audit provides audit logging functionality for tracking security events.
package audit

import (
	"time"
)

const (
	// eventIDRandomLength is the length of random string in event ID
	eventIDRandomLength = 8
)

// EventType represents the type of audit event
type EventType string

const (
	// EventTypeKeyCreate is emitted when a key is created
	EventTypeKeyCreate EventType = "key.create"
	// EventTypeKeyEncrypt is emitted when encryption is performed
	EventTypeKeyEncrypt EventType = "key.encrypt"
	// EventTypeKeyDecrypt is emitted when decryption is performed
	EventTypeKeyDecrypt EventType = "key.decrypt"
	// EventTypeKeySign is emitted when signing is performed
	EventTypeKeySign EventType = "key.sign"
	// EventTypeKeyVerify is emitted when verification is performed
	EventTypeKeyVerify EventType = "key.verify"
	// EventTypeKeyHMAC is emitted when HMAC is computed
	EventTypeKeyHMAC EventType = "key.hmac"
	// EventTypeKeyRotate is emitted when a key is rotated
	EventTypeKeyRotate EventType = "key.rotate"
	// EventTypeKeyRewrap is emitted when ciphertext is re-encrypted
	EventTypeKeyRewrap EventType = "key.rewrap"
	// EventTypeKeyDelete is emitted when a key is deleted
	EventTypeKeyDelete EventType = "key.delete"
	// EventTypeKeyView is emitted when key metadata is viewed
	EventTypeKeyView EventType = "key.view"
	// EventTypeAuthSuccess is emitted on successful authentication
	EventTypeAuthSuccess EventType = "auth.success"
	// EventTypeAuthFailure is emitted on failed authentication
	EventTypeAuthFailure EventType = "auth.failure"
	// EventTypeAuthzDenied is emitted when authorization is denied
	EventTypeAuthzDenied EventType = "authz.denied"
)

// Event represents an audit event
type Event struct {
	ID        string            `json:"id"`
	Type      EventType         `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Identity  string            `json:"identity"`
	KeyID     string            `json:"key_id,omitempty"`
	Operation string            `json:"operation,omitempty"`
	Result    string            `json:"result"` // "success", "failure", "denied"
	Error     string            `json:"error,omitempty"`
	IP        string            `json:"ip,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// NewEvent creates a new audit event
func NewEvent(eventType EventType, identity string) *Event {
	return &Event{
		ID:        generateEventID(),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Identity:  identity,
		Result:    "success",
		Metadata:  make(map[string]string),
	}
}

// WithKeyID sets the key ID
func (e *Event) WithKeyID(keyID string) *Event {
	e.KeyID = keyID
	return e
}

// WithOperation sets the operation
func (e *Event) WithOperation(operation string) *Event {
	e.Operation = operation
	return e
}

// WithResult sets the result
func (e *Event) WithResult(result string) *Event {
	e.Result = result
	return e
}

// WithError sets the error
func (e *Event) WithError(err error) *Event {
	if err != nil {
		e.Error = err.Error()
		e.Result = "failure"
	}
	return e
}

// WithIP sets the IP address
func (e *Event) WithIP(ip string) *Event {
	e.IP = ip
	return e
}

// WithUserAgent sets the user agent
func (e *Event) WithUserAgent(userAgent string) *Event {
	e.UserAgent = userAgent
	return e
}

// WithMetadata adds metadata
func (e *Event) WithMetadata(key, value string) *Event {
	if e.Metadata == nil {
		e.Metadata = make(map[string]string)
	}
	e.Metadata[key] = value
	return e
}

// generateEventID generates a unique event ID
func generateEventID() string {
	// Simple ID generation - in production, use UUID or similar
	return time.Now().Format("20060102150405") + "-" + randomString(eventIDRandomLength)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
