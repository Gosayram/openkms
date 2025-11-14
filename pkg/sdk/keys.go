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

package sdk

import (
	"context"
	"fmt"
)

// CreateKeyRequest represents a key creation request
type CreateKeyRequest struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
}

// CreateKeyResponse represents a key creation response
type CreateKeyResponse struct {
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
}

// GetKeyResponse represents a key metadata response
type GetKeyResponse struct {
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
}

// CreateKey creates a new key
func (c *Client) CreateKey(ctx context.Context, req CreateKeyRequest) (*CreateKeyResponse, error) {
	resp, err := c.doRequestWithRetry(ctx, "POST", "/v1/key", req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var keyResp CreateKeyResponse
	if err := c.parseResponse(resp, &keyResp); err != nil {
		return nil, err
	}

	return &keyResp, nil
}

// GetKey retrieves key metadata
func (c *Client) GetKey(ctx context.Context, keyID string) (*GetKeyResponse, error) {
	path := fmt.Sprintf("/v1/key/%s", keyID)
	resp, err := c.doRequestWithRetry(ctx, "GET", path, nil, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var keyResp GetKeyResponse
	if err := c.parseResponse(resp, &keyResp); err != nil {
		return nil, err
	}

	return &keyResp, nil
}

// RotateKeyRequest represents a key rotation request
type RotateKeyRequest struct {
	Force bool `json:"force,omitempty"`
}

// RotateKeyResponse represents a key rotation response
type RotateKeyResponse struct {
	KeyID      string `json:"key_id"`
	NewVersion uint64 `json:"new_version"`
	Message    string `json:"message,omitempty"`
}

// RotateKey rotates a key
func (c *Client) RotateKey(ctx context.Context, keyID string, force bool) (*RotateKeyResponse, error) {
	req := RotateKeyRequest{
		Force: force,
	}

	path := fmt.Sprintf("/v1/key/%s/rotate", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var rotateResp RotateKeyResponse
	if err := c.parseResponse(resp, &rotateResp); err != nil {
		return nil, err
	}

	return &rotateResp, nil
}
