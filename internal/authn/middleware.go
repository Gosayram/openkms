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

package authn

import (
	"net/http"
	"strings"

	"go.uber.org/zap"
)

const (
	// authHeaderPartsCount is the expected number of parts in Authorization header (scheme and token)
	authHeaderPartsCount = 2
)

// Middleware creates authentication middleware
func Middleware(manager *Manager, logger *zap.Logger, requireAuth bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip authentication for health check
			if r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			var identity *Identity
			var err error

			// Try mTLS first if available
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				mtlsProvider := NewMTLSProvider()
				identity, err = mtlsProvider.AuthenticateFromRequest(r)
				if err == nil {
					// Set identity in context
					ctx := WithIdentity(r.Context(), identity)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Try token authentication
			token := extractToken(r)
			if token != "" {
				identity, err = manager.Authenticate(r.Context(), token)
				if err == nil {
					ctx := WithIdentity(r.Context(), identity)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// If authentication is required and failed
			if requireAuth {
				logger.Warn("Authentication failed",
					zap.String("path", r.URL.Path),
					zap.String("method", r.Method),
					zap.Error(err),
				)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Continue without authentication if not required
			next.ServeHTTP(w, r)
		})
	}
}

// extractToken extracts token from request
func extractToken(r *http.Request) string {
	// Try Authorization header: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", authHeaderPartsCount)
		if len(parts) == authHeaderPartsCount && strings.EqualFold(parts[0], "bearer") {
			return parts[1]
		}
	}

	// Try X-API-Token header
	if token := r.Header.Get("X-API-Token"); token != "" {
		return token
	}

	// Try query parameter (less secure, but sometimes needed)
	if token := r.URL.Query().Get("token"); token != "" {
		return token
	}

	return ""
}

// RequireAuth creates middleware that requires authentication
func RequireAuth(manager *Manager, logger *zap.Logger) func(http.Handler) http.Handler {
	return Middleware(manager, logger, true)
}

// OptionalAuth creates middleware with optional authentication
func OptionalAuth(manager *Manager, logger *zap.Logger) func(http.Handler) http.Handler {
	return Middleware(manager, logger, false)
}
