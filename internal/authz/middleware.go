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

// Package authz provides authorization middleware and permission checking functionality.
//
//nolint:goimports // imports are properly formatted, golangci-lint cache issue
package authz

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/keystore"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

const httpMethodPOST = "POST"

// MiddlewareConfig contains configuration for authorization middleware
type MiddlewareConfig struct {
	Engine   *Engine
	Logger   *zap.Logger
	KeyStore *keystore.Store // Optional: required for ABAC to extract key attributes
}

// Middleware creates authorization middleware
func Middleware(engine *Engine, logger *zap.Logger) func(http.Handler) http.Handler {
	return MiddlewareWithConfig(MiddlewareConfig{
		Engine: engine,
		Logger: logger,
	})
}

// MiddlewareWithConfig creates authorization middleware with configuration
func MiddlewareWithConfig(config MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get identity from context
			identity, ok := authn.GetIdentity(r.Context())
			if !ok {
				config.Logger.Warn("Identity not found in context")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Extract permission and key ID from request
			permission, keyID := extractPermissionAndKey(r)
			if permission == "" {
				// No specific permission required, allow
				next.ServeHTTP(w, r)
				return
			}

			var allowed bool
			var err error

			// Use ABAC if enabled, otherwise use RBAC
			if config.Engine.IsABACEngine() {
				allowed, err = checkPermissionWithABAC(
					r.Context(),
					config.Engine,
					identity,
					permission,
					keyID,
					config.KeyStore,
					config.Logger,
				)
			} else {
				// Use legacy RBAC check
				allowed, err = config.Engine.CheckPermission(identity.ID, permission, keyID)
			}

			if err != nil {
				config.Logger.Error("Authorization check failed",
					zap.String("identity", identity.ID),
					zap.String("permission", string(permission)),
					zap.String("key_id", keyID),
					zap.Error(err),
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !allowed {
				config.Logger.Warn("Permission denied",
					zap.String("identity", identity.ID),
					zap.String("permission", string(permission)),
					zap.String("key_id", keyID),
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// checkPermissionWithABAC checks permission using ABAC attributes
func checkPermissionWithABAC(
	ctx context.Context,
	engine *Engine,
	identity *authn.Identity,
	permission Permission,
	keyID string,
	keyStore *keystore.Store,
	logger *zap.Logger,
) (bool, error) {
	// Extract subject attributes
	subjectAttrs := ExtractSubjectAttributes(identity)

	// Extract object attributes
	var objectAttrs ObjectAttributes
	if keyID != "" && keyStore != nil {
		// Try to get key metadata
		keyMetadata, err := keyStore.GetKey(ctx, keyID)
		if err == nil && keyMetadata != nil {
			objectAttrs = ExtractObjectAttributes(keyMetadata)
		} else {
			// Key not found or error, create minimal object attributes
			objectAttrs = ObjectAttributes{
				ID:       keyID,
				Metadata: make(map[string]string),
			}
		}
	} else {
		// No key ID or no keystore, create minimal object attributes
		objectAttrs = ObjectAttributes{
			ID:       keyID,
			Metadata: make(map[string]string),
		}
	}

	// Build environment attributes
	envAttrs := EnvironmentAttributes{
		Time:      time.Now(),
		Metadata:  make(map[string]string),
		UserAgent: "", // Can be extracted from request if needed
	}

	// Build attributes
	attrs := BuildAttributes(
		subjectAttrs,
		objectAttrs,
		string(permission),
		envAttrs,
	)

	// Check permission with attributes
	return engine.CheckPermissionWithAttributes(attrs)
}

// extractPermissionAndKey extracts permission and key ID from request
func extractPermissionAndKey(r *http.Request) (permission Permission, keyID string) {
	path := r.URL.Path
	method := r.Method
	keyID = chi.URLParam(r, "id")

	// Check POST operations first
	if method == httpMethodPOST {
		if perm := checkPOSTPermission(path); perm != "" {
			if path == "/v1/key" {
				return perm, ""
			}
			return perm, keyID
		}
	}

	// Check GET/DELETE operations
	if method == "GET" && strings.Contains(path, "/key/") {
		return PermissionView, keyID
	}
	if method == "DELETE" && strings.Contains(path, "/key/") {
		return PermissionDelete, keyID
	}

	return "", ""
}

// checkPOSTPermission checks POST operations and returns corresponding permission
func checkPOSTPermission(path string) Permission {
	if path == "/v1/key" {
		return PermissionCreate
	}
	if strings.HasSuffix(path, "/encrypt") {
		return PermissionEncrypt
	}
	if strings.HasSuffix(path, "/decrypt") {
		return PermissionDecrypt
	}
	if strings.HasSuffix(path, "/sign") {
		return PermissionSign
	}
	if strings.HasSuffix(path, "/verify") {
		return PermissionVerify
	}
	if strings.HasSuffix(path, "/hmac") {
		return PermissionHMAC
	}
	if strings.HasSuffix(path, "/rotate") {
		return PermissionRotate
	}
	return ""
}
