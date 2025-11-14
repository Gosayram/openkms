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

// Package server provides HTTP handlers for the OpenKMS API endpoints.
//
//nolint:goimports // imports are properly formatted, golangci-lint cache issue
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Gosayram/openkms/internal/audit"
	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/authz"
	"github.com/Gosayram/openkms/internal/cryptoengine"
	"github.com/Gosayram/openkms/internal/keystore"
	"github.com/Gosayram/openkms/internal/metrics"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

// Handlers contains all HTTP handlers
type Handlers struct {
	logger       *zap.Logger
	keyStore     *keystore.Store
	cryptoEngine *cryptoengine.CryptoEngine
	auditLogger  *audit.Logger
	authzEngine  *authz.Engine
}

// NewHandlers creates new HTTP handlers
//
//nolint:lll // function signature requires multiple long parameter names
func NewHandlers(logger *zap.Logger, keyStore *keystore.Store, cryptoEngine *cryptoengine.CryptoEngine, auditLogger *audit.Logger, authzEngine *authz.Engine) *Handlers {
	return &Handlers{
		logger:       logger,
		keyStore:     keyStore,
		cryptoEngine: cryptoEngine,
		auditLogger:  auditLogger,
		authzEngine:  authzEngine,
	}
}

// CreateKey handles key creation
func (h *Handlers) CreateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Validate request
	if req.ID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}
	if req.Algorithm == "" {
		h.respondError(w, http.StatusBadRequest, "algorithm is required", nil)
		return
	}

	// Map request type to keystore type
	keyType := keystore.KeyTypeDEK
	if req.Type != "" {
		keyType = keystore.KeyType(req.Type)
	}

	// Map request algorithm to keystore algorithm
	algorithm := keystore.Algorithm(req.Algorithm)

	// Create key metadata
	metadata := &keystore.KeyMetadata{
		ID:        req.ID,
		Type:      keyType,
		Algorithm: algorithm,
		State:     keystore.KeyStateCreated,
	}

	// Generate key material
	keyMaterial, err := h.cryptoEngine.GenerateKey(ctx, req.Algorithm)
	if err != nil {
		h.logger.Error("Failed to generate key material", zap.Error(err), zap.String("algorithm", req.Algorithm))
		h.respondError(w, http.StatusInternalServerError, "failed to generate key", err)
		return
	}

	// Save metadata
	if err := h.keyStore.CreateKey(ctx, metadata); err != nil {
		h.logger.Error("Failed to create key metadata", zap.Error(err))
		h.respondError(w, http.StatusConflict, "key already exists", err)
		return
	}

	// Save key material (already encrypted by envelope backend)
	if err := h.keyStore.SaveKeyMaterial(ctx, req.ID, metadata.Version, keyMaterial); err != nil {
		h.logger.Error("Failed to save key material", zap.Error(err))
		// Try to clean up metadata
		_ = h.keyStore.DeleteKey(ctx, req.ID)
		h.respondError(w, http.StatusInternalServerError, "failed to save key material", err)
		return
	}

	// Activate key
	if err := h.keyStore.UpdateKeyState(ctx, req.ID, keystore.KeyStateActive); err != nil {
		h.logger.Error("Failed to activate key", zap.Error(err))
		// Key is created but not activated - this is acceptable
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyCreate, identity.ID)
	event.WithKeyID(req.ID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusCreated, CreateKeyResponse{
		ID:      req.ID,
		Message: "Key created successfully",
	})
}

// GetKey handles key metadata retrieval
func (h *Handlers) GetKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyView, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, GetKeyResponse{
		ID:      metadata.ID,
		Message: "Key retrieved successfully",
	})
}

// Encrypt handles encryption requests
func (h *Handlers) Encrypt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Check if key can encrypt
	if !metadata.CanEncrypt() {
		h.respondError(w, http.StatusForbidden, "key is not active", nil)
		return
	}

	// Get key material (automatically decrypted by envelope backend)
	keyMaterial, err := h.keyStore.GetKeyMaterial(ctx, keyID, metadata.Version)
	if err != nil {
		h.logger.Error("Failed to get key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to get key material", err)
		return
	}

	// Encrypt
	encrypted, err := h.cryptoEngine.Encrypt(ctx, keyMaterial, string(metadata.Algorithm), req.Plaintext, req.AAD)
	if err != nil {
		h.logger.Error("Failed to encrypt", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to encrypt", err)
		return
	}

	// Record metrics
	metrics.RecordKeyUsage(keyID, "encrypt")

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyEncrypt, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, EncryptResponse{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Message:    "Encryption successful",
	})
}

// Decrypt handles decryption requests
func (h *Handlers) Decrypt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Check if key can decrypt
	if !metadata.CanDecrypt() {
		h.respondError(w, http.StatusForbidden, "key cannot be used for decryption", nil)
		return
	}

	// Get key material (automatically decrypted by envelope backend)
	keyMaterial, err := h.keyStore.GetKeyMaterial(ctx, keyID, metadata.Version)
	if err != nil {
		h.logger.Error("Failed to get key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to get key material", err)
		return
	}

	// Decrypt
	encrypted := &cryptoengine.EncryptedData{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		AAD:        req.AAD,
		Algorithm:  string(metadata.Algorithm),
	}

	plaintext, err := h.cryptoEngine.Decrypt(ctx, keyMaterial, string(metadata.Algorithm), encrypted)
	if err != nil {
		h.logger.Error("Failed to decrypt", zap.Error(err))
		h.respondError(w, http.StatusBadRequest, "failed to decrypt", err)
		return
	}

	// Record metrics
	metrics.RecordKeyUsage(keyID, "decrypt")

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyDecrypt, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, DecryptResponse{
		Plaintext: plaintext,
		Message:   "Decryption successful",
	})
}

// Sign handles signing requests
//
//nolint:dupl // similar structure to HMAC is intentional, both use handleSigningOperation
func (h *Handlers) Sign(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	op := func(ctx context.Context, keyMaterial []byte, algorithm string, data []byte) ([]byte, error) {
		return h.cryptoEngine.Sign(ctx, keyMaterial, algorithm, data)
	}
	responseBuilder := func(result []byte) interface{} {
		return SignResponse{
			Signature: result,
			Message:   "Signing successful",
		}
	}
	h.handleSigningOperation(
		w, r, &req,
		audit.EventTypeKeySign,
		"key cannot be used for signing",
		"failed to sign",
		"Signing successful",
		responseBuilder,
		op,
	)
}

// Verify handles signature verification requests
func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Get key material (automatically decrypted by envelope backend)
	// For verification, we need the public key, but for simplicity we'll use the private key
	// In production, we should store public keys separately
	keyMaterial, err := h.keyStore.GetKeyMaterial(ctx, keyID, metadata.Version)
	if err != nil {
		h.logger.Error("Failed to get key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to get key material", err)
		return
	}

	// Verify
	valid, err := h.cryptoEngine.Verify(ctx, keyMaterial, string(metadata.Algorithm), req.Data, req.Signature)
	if err != nil {
		h.logger.Error("Failed to verify", zap.Error(err))
		h.respondError(w, http.StatusBadRequest, "failed to verify signature", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyVerify, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	if !valid {
		event.WithResult("failure")
	}
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, VerifyResponse{
		Valid:   valid,
		Message: "Verification completed",
	})
}

// HMAC handles HMAC computation requests
//
//nolint:dupl // similar structure to Sign is intentional, both use handleSigningOperation
func (h *Handlers) HMAC(w http.ResponseWriter, r *http.Request) {
	var req HMACRequest
	op := func(ctx context.Context, keyMaterial []byte, algorithm string, data []byte) ([]byte, error) {
		return h.cryptoEngine.HMAC(ctx, keyMaterial, algorithm, data)
	}
	responseBuilder := func(result []byte) interface{} {
		return HMACResponse{
			MAC:     result,
			Message: "HMAC computed successfully",
		}
	}
	h.handleSigningOperation(
		w, r, &req,
		audit.EventTypeKeyHMAC,
		"key cannot be used for HMAC",
		"failed to compute HMAC",
		"HMAC computed successfully",
		responseBuilder,
		op,
	)
}

// GetKeyVersions handles key version listing
func (h *Handlers) GetKeyVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	// Get key metadata to verify it exists
	_, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// List versions
	versions, err := h.keyStore.ListKeyVersions(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to list key versions", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to list versions", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyView, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, GetKeyVersionsResponse{
		KeyID:    keyID,
		Versions: versions,
		Message:  "Versions retrieved successfully",
	})
}

// GetRandom handles random byte generation
func (h *Handlers) GetRandom(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	bytesStr := r.URL.Query().Get("bytes")
	if bytesStr == "" {
		bytesStr = "32" // Default
	}

	bytes, err := strconv.Atoi(bytesStr)
	if err != nil || bytes <= 0 || bytes > 1024 {
		h.respondError(w, http.StatusBadRequest, "invalid bytes parameter (1-1024)", err)
		return
	}

	// Generate random bytes
	randomBytes, err := h.cryptoEngine.GenerateRandom(ctx, bytes)
	if err != nil {
		h.logger.Error("Failed to generate random bytes", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to generate random bytes", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyView, identity.ID)
	event.WithOperation("get_random").WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, GetRandomResponse{
		Bytes:   bytes,
		Random:  randomBytes,
		Message: "Random bytes generated successfully",
	})
}

// GetAuditLogs handles audit log retrieval
func (h *Handlers) GetAuditLogs(w http.ResponseWriter, _ *http.Request) {
	// TODO: Implement audit log retrieval
	h.logger.Info("GetAuditLogs called")

	h.respondJSON(w, http.StatusOK, GetAuditLogsResponse{
		Message: "Audit log retrieval not yet implemented",
	})
}

// Helper methods

func (h *Handlers) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode response", zap.Error(err))
	}
}

func (h *Handlers) respondError(w http.ResponseWriter, status int, message string, err error) {
	h.logger.Error(message, zap.Error(err))
	details := ""
	if err != nil {
		details = err.Error()
	}
	h.respondJSON(w, status, ErrorResponse{
		Error:   message,
		Details: details,
	})
}

// signingRequest is an interface for requests that contain data to sign
type signingRequest interface {
	GetData() []byte
}

// GetData returns the data field from SignRequest
func (r *SignRequest) GetData() []byte {
	return r.Data
}

// GetData returns the data field from HMACRequest
func (r *HMACRequest) GetData() []byte {
	return r.Data
}

// handleSigningOperation is a helper function that handles common logic for signing operations
func (h *Handlers) handleSigningOperation(
	w http.ResponseWriter,
	r *http.Request,
	req signingRequest,
	eventType audit.EventType,
	forbiddenMsg, errorMsg, _ string,
	responseBuilder func([]byte) interface{},
	op func(context.Context, []byte, string, []byte) ([]byte, error),
) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Check if key can sign
	if !metadata.CanSign() {
		h.respondError(w, http.StatusForbidden, forbiddenMsg, nil)
		return
	}

	// Get key material (automatically decrypted by envelope backend)
	keyMaterial, err := h.keyStore.GetKeyMaterial(ctx, keyID, metadata.Version)
	if err != nil {
		h.logger.Error("Failed to get key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to get key material", err)
		return
	}

	// Execute operation
	result, err := op(ctx, keyMaterial, string(metadata.Algorithm), req.GetData())
	if err != nil {
		h.logger.Error(errorMsg, zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, errorMsg, err)
		return
	}

	// Record metrics
	operation := "sign"
	if eventType == audit.EventTypeKeyHMAC {
		operation = "hmac"
	}
	metrics.RecordKeyUsage(keyID, operation)

	// Audit log
	event := audit.NewEvent(eventType, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, responseBuilder(result))
}

// RotateKey handles key rotation requests
func (h *Handlers) RotateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	var req RotateKeyRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid request body", err)
			return
		}
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Check if key can be rotated (must be active unless forced)
	if !req.Force && metadata.State != keystore.KeyStateActive {
		h.respondError(w, http.StatusForbidden, "key must be active to rotate", nil)
		return
	}

	// Get old key material to generate new key
	_, err = h.keyStore.GetKeyMaterial(ctx, keyID, metadata.Version)
	if err != nil {
		h.logger.Error("Failed to get key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to get key material", err)
		return
	}

	// Rotate key (increment version)
	newVersion, err := h.keyStore.RotateKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to rotate key", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to rotate key", err)
		return
	}

	// Generate new key material using crypto engine
	newKeyMaterial, err := h.cryptoEngine.GenerateKey(ctx, string(metadata.Algorithm))
	if err != nil {
		h.logger.Error("Failed to generate new key", zap.Error(err))
		// Try to rollback version increment (best effort)
		_ = h.keyStore.UpdateKeyState(ctx, keyID, metadata.State)
		h.respondError(w, http.StatusInternalServerError, "failed to generate new key", err)
		return
	}

	// Save new key material
	if err := h.keyStore.SaveKeyMaterial(ctx, keyID, newVersion, newKeyMaterial); err != nil {
		h.logger.Error("Failed to save new key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to save new key material", err)
		return
	}

	// Record metrics
	metrics.RecordKeyRotation(keyID)

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyRotate, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, RotateKeyResponse{
		KeyID:      keyID,
		NewVersion: newVersion,
		Message:    "Key rotated successfully",
	})
}

// Rewrap handles ciphertext re-encryption requests
// This allows re-encrypting data with a new key version without exposing plaintext
func (h *Handlers) Rewrap(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	keyID := chi.URLParam(r, "id")
	if keyID == "" {
		h.respondError(w, http.StatusBadRequest, "key ID is required", nil)
		return
	}

	var req RewrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Get key metadata
	metadata, err := h.keyStore.GetKey(ctx, keyID)
	if err != nil {
		h.logger.Error("Failed to get key", zap.Error(err), zap.String("key_id", keyID))
		h.respondError(w, http.StatusNotFound, "key not found", err)
		return
	}

	// Determine old version (use current if not specified)
	oldVersion := req.OldVersion
	if oldVersion == 0 {
		oldVersion = metadata.Version
	}

	// Get old key material
	oldKeyMaterial, err := h.keyStore.GetKeyMaterial(ctx, keyID, oldVersion)
	if err != nil {
		h.logger.Error("Failed to get old key material", zap.Error(err))
		h.respondError(w, http.StatusNotFound, "old key version not found", err)
		return
	}

	// Decrypt with old key
	encrypted := &cryptoengine.EncryptedData{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		AAD:        req.AAD,
		Algorithm:  string(metadata.Algorithm),
	}

	plaintext, err := h.cryptoEngine.Decrypt(ctx, oldKeyMaterial, string(metadata.Algorithm), encrypted)
	if err != nil {
		h.logger.Error("Failed to decrypt with old key", zap.Error(err))
		h.respondError(w, http.StatusBadRequest, "failed to decrypt with old key", err)
		return
	}

	// Get new key material (current version)
	newKeyMaterial, err := h.keyStore.GetKeyMaterial(ctx, keyID, metadata.Version)
	if err != nil {
		h.logger.Error("Failed to get new key material", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to get new key material", err)
		return
	}

	// Encrypt with new key
	newEncrypted, err := h.cryptoEngine.Encrypt(ctx, newKeyMaterial, string(metadata.Algorithm), plaintext, req.AAD)
	if err != nil {
		h.logger.Error("Failed to encrypt with new key", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to encrypt with new key", err)
		return
	}

	// Record metrics
	metrics.RecordKeyUsage(keyID, "rewrap")

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyRewrap, identity.ID)
	event.WithKeyID(keyID).WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, RewrapResponse{
		Ciphertext: newEncrypted.Ciphertext,
		Nonce:      newEncrypted.Nonce,
		Message:    "Ciphertext re-encrypted successfully",
	})
}

// CreatePolicy creates a new policy
//
//nolint:dupl // similar structure to DeletePolicy is intentional
func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Check if using Casbin engine
	if !h.isCasbinEngine() {
		h.respondError(w, http.StatusNotImplemented, "policy management requires Casbin engine", nil)
		return
	}

	// Get Casbin engine
	casbinEngine := h.getCasbinEngine()
	if casbinEngine == nil {
		h.respondError(w, http.StatusInternalServerError, "Casbin engine not available", nil)
		return
	}

	// Add policy
	added, err := casbinEngine.AddPolicy(req.Subject, req.Object, req.Action)
	if err != nil {
		h.logger.Error("Failed to add policy", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to add policy", err)
		return
	}

	if !added {
		h.respondError(w, http.StatusConflict, "policy already exists", nil)
		return
	}

	// Save policies
	if err := casbinEngine.SavePolicy(); err != nil {
		h.logger.Error("Failed to save policies", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to save policies", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyCreate, identity.ID)
	event.WithOperation("create_policy").WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, PolicyResponse{
		Subject: req.Subject,
		Object:  req.Object,
		Action:  req.Action,
		Message: "Policy created successfully",
	})
}

// DeletePolicy deletes a policy
//
//nolint:dupl // similar structure to CreatePolicy is intentional
func (h *Handlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Check if using Casbin engine
	if !h.isCasbinEngine() {
		h.respondError(w, http.StatusNotImplemented, "policy management requires Casbin engine", nil)
		return
	}

	// Get Casbin engine
	casbinEngine := h.getCasbinEngine()
	if casbinEngine == nil {
		h.respondError(w, http.StatusInternalServerError, "Casbin engine not available", nil)
		return
	}

	// Remove policy
	removed, err := casbinEngine.RemovePolicy(req.Subject, req.Object, req.Action)
	if err != nil {
		h.logger.Error("Failed to remove policy", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to remove policy", err)
		return
	}

	if !removed {
		h.respondError(w, http.StatusNotFound, "policy not found", nil)
		return
	}

	// Save policies
	if err := casbinEngine.SavePolicy(); err != nil {
		h.logger.Error("Failed to save policies", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to save policies", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyDelete, identity.ID)
	event.WithOperation("delete_policy").WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, PolicyResponse{
		Subject: req.Subject,
		Object:  req.Object,
		Action:  req.Action,
		Message: "Policy deleted successfully",
	})
}

// ListPolicies lists all policies
func (h *Handlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	// Check if using Casbin engine
	if !h.isCasbinEngine() {
		h.respondError(w, http.StatusNotImplemented, "policy management requires Casbin engine", nil)
		return
	}

	// Get Casbin engine
	casbinEngine := h.getCasbinEngine()
	if casbinEngine == nil {
		h.respondError(w, http.StatusInternalServerError, "Casbin engine not available", nil)
		return
	}

	// Get all policies from the enforcer
	// Note: This is a simplified implementation
	// In production, you might want to filter by user or role
	allPolicies := casbinEngine.GetAllPolicies()
	if allPolicies == nil {
		allPolicies = [][]string{}
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyView, identity.ID)
	event.WithOperation("list_policies").WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, ListPoliciesResponse{
		Policies: allPolicies,
		Message:  "Policies retrieved successfully",
	})
}

// AssignRole assigns a role to a user
func (h *Handlers) AssignRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body", err)
		return
	}

	// Check if using Casbin engine
	if !h.isCasbinEngine() {
		h.respondError(w, http.StatusNotImplemented, "role management requires Casbin engine", nil)
		return
	}

	// Get Casbin engine
	casbinEngine := h.getCasbinEngine()
	if casbinEngine == nil {
		h.respondError(w, http.StatusInternalServerError, "Casbin engine not available", nil)
		return
	}

	// Add role for user
	added, err := casbinEngine.AddRoleForUser(req.User, req.Role)
	if err != nil {
		h.logger.Error("Failed to assign role", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to assign role", err)
		return
	}

	if !added {
		h.respondError(w, http.StatusConflict, "role already assigned", nil)
		return
	}

	// Save policies
	if err := casbinEngine.SavePolicy(); err != nil {
		h.logger.Error("Failed to save policies", zap.Error(err))
		h.respondError(w, http.StatusInternalServerError, "failed to save policies", err)
		return
	}

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyCreate, identity.ID)
	event.WithOperation("assign_role").WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, RoleResponse{
		User:    req.User,
		Role:    req.Role,
		Message: "Role assigned successfully",
	})
}

// GetUserRoles gets all roles for a user
func (h *Handlers) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := h.getIdentity(ctx)

	userID := chi.URLParam(r, "user")
	if userID == "" {
		h.respondError(w, http.StatusBadRequest, "user ID is required", nil)
		return
	}

	// Check if using Casbin engine
	if !h.isCasbinEngine() {
		h.respondError(w, http.StatusNotImplemented, "role management requires Casbin engine", nil)
		return
	}

	// Get Casbin engine
	casbinEngine := h.getCasbinEngine()
	if casbinEngine == nil {
		h.respondError(w, http.StatusInternalServerError, "Casbin engine not available", nil)
		return
	}

	// Get roles for user
	roles := casbinEngine.GetRolesForUser(userID)

	// Audit log
	event := audit.NewEvent(audit.EventTypeKeyView, identity.ID)
	event.WithOperation("get_user_roles").WithResult("success")
	_ = h.auditLogger.Log(ctx, event)

	h.respondJSON(w, http.StatusOK, ListRolesResponse{
		Roles:   roles,
		Message: "Roles retrieved successfully",
	})
}

// isCasbinEngine checks if the engine is using Casbin
func (h *Handlers) isCasbinEngine() bool {
	return h.authzEngine != nil && h.authzEngine.IsCasbinEngine()
}

// getCasbinEngine gets the Casbin engine from the authorization engine
func (h *Handlers) getCasbinEngine() *authz.CasbinEngine {
	if h.authzEngine == nil {
		return nil
	}
	return h.authzEngine.GetCasbinEngine()
}

// getIdentity retrieves identity from request context
func (h *Handlers) getIdentity(ctx context.Context) *authn.Identity {
	identity, ok := authn.GetIdentity(ctx)
	if !ok {
		// Return anonymous identity if not found
		return &authn.Identity{
			ID:   "anonymous",
			Type: "anonymous",
		}
	}
	return identity
}
