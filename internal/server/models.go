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

// Request/Response models

// CreateKeyRequest represents a request to create a new key
type CreateKeyRequest struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
}

// CreateKeyResponse represents a response from key creation
type CreateKeyResponse struct {
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
}

// GetKeyResponse represents a response from key retrieval
type GetKeyResponse struct {
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
}

// EncryptRequest represents a request to encrypt data
type EncryptRequest struct {
	Plaintext []byte `json:"plaintext"`
	AAD       []byte `json:"aad,omitempty"`
}

// EncryptResponse represents a response from encryption
type EncryptResponse struct {
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Message    string `json:"message,omitempty"`
}

// DecryptRequest represents a request to decrypt data
type DecryptRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	AAD        []byte `json:"aad,omitempty"`
}

// DecryptResponse represents a response from decryption
type DecryptResponse struct {
	Plaintext []byte `json:"plaintext,omitempty"`
	Message   string `json:"message,omitempty"`
}

// SignRequest represents a request to sign data
type SignRequest struct {
	Data []byte `json:"data"`
}

// SignResponse represents a response from signing
type SignResponse struct {
	Signature []byte `json:"signature,omitempty"`
	Message   string `json:"message,omitempty"`
}

// VerifyRequest represents a request to verify a signature
type VerifyRequest struct {
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
}

// VerifyResponse represents a response from signature verification
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// HMACRequest represents a request to compute HMAC
type HMACRequest struct {
	Data []byte `json:"data"`
}

// HMACResponse represents a response from HMAC computation
type HMACResponse struct {
	MAC     []byte `json:"mac,omitempty"`
	Message string `json:"message,omitempty"`
}

// GetKeyVersionsResponse represents a response from key version listing
type GetKeyVersionsResponse struct {
	KeyID    string   `json:"key_id"`
	Versions []uint64 `json:"versions,omitempty"`
	Message  string   `json:"message,omitempty"`
}

// GetRandomResponse represents a response from random byte generation
type GetRandomResponse struct {
	Bytes   int    `json:"bytes"`
	Random  []byte `json:"random,omitempty"`
	Message string `json:"message,omitempty"`
}

// GetAuditLogsResponse represents a response from audit log retrieval
type GetAuditLogsResponse struct {
	Logs    []interface{} `json:"logs,omitempty"`
	Message string        `json:"message,omitempty"`
}

// RotateKeyRequest represents a request to rotate a key
type RotateKeyRequest struct {
	// Optional: force rotation even if key is not active
	Force bool `json:"force,omitempty"`
}

// RotateKeyResponse represents a response from key rotation
type RotateKeyResponse struct {
	KeyID      string `json:"key_id"`
	NewVersion uint64 `json:"new_version"`
	Message    string `json:"message,omitempty"`
}

// RewrapRequest represents a request to rewrap ciphertext
type RewrapRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	AAD        []byte `json:"aad,omitempty"`
	OldVersion uint64 `json:"old_version,omitempty"` // If not specified, uses current version
}

// RewrapResponse represents a response from rewrap operation
type RewrapResponse struct {
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	Message    string `json:"message,omitempty"`
}

// PolicyRequest represents a request to create/update a policy
type PolicyRequest struct {
	Subject string `json:"subject"` // User or role
	Object  string `json:"object"`  // Key ID or pattern
	Action  string `json:"action"`  // Permission action
}

// PolicyResponse represents a policy response
type PolicyResponse struct {
	Subject string `json:"subject"`
	Object  string `json:"object"`
	Action  string `json:"action"`
	Message string `json:"message,omitempty"`
}

// RoleRequest represents a request to assign a role
type RoleRequest struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// RoleResponse represents a role assignment response
type RoleResponse struct {
	User    string `json:"user"`
	Role    string `json:"role"`
	Message string `json:"message,omitempty"`
}

// ListPoliciesResponse represents a response with list of policies
type ListPoliciesResponse struct {
	Policies [][]string `json:"policies,omitempty"`
	Message  string     `json:"message,omitempty"`
}

// ListRolesResponse represents a response with list of roles
type ListRolesResponse struct {
	Roles   []string `json:"roles,omitempty"`
	Message string   `json:"message,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
