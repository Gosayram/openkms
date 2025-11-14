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

package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Gosayram/openkms/internal/metrics"
)

const (
	// httpStatusClientError is the minimum HTTP status code for client errors
	httpStatusClientError = 400
	// httpStatusServerError is the minimum HTTP status code for server errors
	httpStatusServerError = 500
)

// MetricsMiddleware records metrics for HTTP requests
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		ww := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Execute handler
		next.ServeHTTP(ww, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		operation := extractOperation(r)
		status := strconv.Itoa(ww.statusCode)
		statusLabel := "success"
		if ww.statusCode >= httpStatusClientError {
			statusLabel = "error"
		}

		metrics.RecordOperation(operation, statusLabel, duration)
		metrics.OperationTotal.WithLabelValues(operation, status).Inc()

		if ww.statusCode >= httpStatusClientError {
			errorType := "client_error"
			if ww.statusCode >= httpStatusServerError {
				errorType = "server_error"
			}
			metrics.RecordError(operation, errorType)
		}
	})
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

// extractOperation extracts operation name from request path
func extractOperation(r *http.Request) string {
	path := r.URL.Path
	method := r.Method

	// Map common patterns to operation names
	if path == "/health" {
		return "health_check"
	}
	if path == "/metrics" {
		return "metrics"
	}

	// Extract operation from path pattern
	// e.g., /v1/key/{id}/encrypt -> encrypt
	if path != "" {
		// Remove /v1 prefix if present
		if len(path) > 3 && path[:3] == "/v1" {
			path = path[3:]
		}

		// Extract last segment as operation
		parts := splitPath(path)
		if len(parts) > 0 {
			lastPart := parts[len(parts)-1]
			if lastPart != "" && lastPart != "key" {
				return method + "_" + lastPart
			}
		}
	}

	return method + "_" + path
}

// splitPath splits a path into segments
func splitPath(path string) []string {
	if path == "" || path == "/" {
		return []string{}
	}

	// Remove leading slash
	if path[0] == '/' {
		path = path[1:]
	}

	// Split by slash
	parts := []string{}
	current := ""
	for _, char := range path {
		if char == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	return parts
}
