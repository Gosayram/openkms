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

//nolint:goimports // imports are properly formatted, golangci-lint cache issue
package audit

import (
	"net/http"
	"strings"

	"github.com/Gosayram/openkms/internal/authn"
	"go.uber.org/zap"
)

const httpMethodPOST = "POST"

// Middleware creates audit logging middleware
func Middleware(auditLogger *Logger, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create response writer wrapper to capture status
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Execute handler
			next.ServeHTTP(rw, r)

			// Get identity from context
			identity, ok := authn.GetIdentity(r.Context())
			if !ok {
				identity = &authn.Identity{ID: "unknown", Type: "unknown"}
			}

			// Determine event type based on request
			eventType := determineEventType(r, rw.statusCode)

			// Create audit event
			event := NewEvent(eventType, identity.ID).
				WithIP(r.RemoteAddr).
				WithUserAgent(r.UserAgent()).
				WithOperation(r.Method + " " + r.URL.Path)

			// Extract key ID if present
			if keyID := r.URL.Query().Get("key_id"); keyID != "" {
				event.WithKeyID(keyID)
			}

			// Set result based on status code
			switch {
			case rw.statusCode >= 200 && rw.statusCode < 300:
				event.WithResult("success")
			case rw.statusCode == http.StatusUnauthorized || rw.statusCode == http.StatusForbidden:
				event.WithResult("denied")
			default:
				event.WithResult("failure")
			}

			// Log audit event
			if err := auditLogger.Log(r.Context(), event); err != nil {
				logger.Error("Failed to log audit event", zap.Error(err))
			}
		})
	}
}

// determineEventType determines audit event type from request
func determineEventType(r *http.Request, statusCode int) EventType {
	// Authentication events
	if statusCode == http.StatusUnauthorized {
		return EventTypeAuthFailure
	}

	// Authorization events
	if statusCode == http.StatusForbidden {
		return EventTypeAuthzDenied
	}

	// Key operation events
	return determineKeyOperationEventType(r)
}

// determineKeyOperationEventType determines event type for key operations
func determineKeyOperationEventType(r *http.Request) EventType {
	path := r.URL.Path
	method := r.Method

	// Check for POST operations with path patterns
	if method == httpMethodPOST {
		if eventType := checkPOSTOperation(path); eventType != EventTypeAuthSuccess {
			return eventType
		}
	}

	// Check for GET/DELETE operations
	if method == "GET" && strings.Contains(path, "/key/") {
		return EventTypeKeyView
	}
	if method == "DELETE" && strings.Contains(path, "/key/") {
		return EventTypeKeyDelete
	}

	return EventTypeAuthSuccess
}

// checkPOSTOperation checks POST operations and returns corresponding event type
func checkPOSTOperation(path string) EventType {
	if path == "/v1/key" {
		return EventTypeKeyCreate
	}
	if strings.Contains(path, "/encrypt") {
		return EventTypeKeyEncrypt
	}
	if strings.Contains(path, "/decrypt") {
		return EventTypeKeyDecrypt
	}
	if strings.Contains(path, "/sign") {
		return EventTypeKeySign
	}
	if strings.Contains(path, "/verify") {
		return EventTypeKeyVerify
	}
	if strings.Contains(path, "/hmac") {
		return EventTypeKeyHMAC
	}
	if strings.Contains(path, "/rotate") {
		return EventTypeKeyRotate
	}
	return EventTypeAuthSuccess
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
