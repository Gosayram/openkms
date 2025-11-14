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
	"encoding/base64"
	"fmt"
)

// EncryptRequest represents an encryption request
type EncryptRequest struct {
	Plaintext string `json:"plaintext"`     // Base64 encoded
	AAD       string `json:"aad,omitempty"` // Base64 encoded
}

// EncryptResponse represents an encryption response
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext,omitempty"` // Base64 encoded
	Nonce      string `json:"nonce,omitempty"`      // Base64 encoded
	Message    string `json:"message,omitempty"`
}

// DecryptRequest represents a decryption request
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`    // Base64 encoded
	Nonce      string `json:"nonce"`         // Base64 encoded
	AAD        string `json:"aad,omitempty"` // Base64 encoded
}

// DecryptResponse represents a decryption response
type DecryptResponse struct {
	Plaintext string `json:"plaintext,omitempty"` // Base64 encoded
	Message   string `json:"message,omitempty"`
}

// Encrypt encrypts data using the specified key
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext, aad []byte) (*EncryptResponse, error) {
	req := EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}

	if len(aad) > 0 {
		req.AAD = base64.StdEncoding.EncodeToString(aad)
	}

	path := fmt.Sprintf("/v1/key/%s/encrypt", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var encryptResp EncryptResponse
	if err := c.parseResponse(resp, &encryptResp); err != nil {
		return nil, err
	}

	return &encryptResp, nil
}

// Decrypt decrypts data using the specified key
func (c *Client) Decrypt(ctx context.Context, keyID string, ciphertext, nonce, aad []byte) (*DecryptResponse, error) {
	req := DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}

	if len(aad) > 0 {
		req.AAD = base64.StdEncoding.EncodeToString(aad)
	}

	path := fmt.Sprintf("/v1/key/%s/decrypt", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var decryptResp DecryptResponse
	if err := c.parseResponse(resp, &decryptResp); err != nil {
		return nil, err
	}

	return &decryptResp, nil
}

// SignRequest represents a signing request
type SignRequest struct {
	Data string `json:"data"` // Base64 encoded
}

// SignResponse represents a signing response
type SignResponse struct {
	Signature string `json:"signature,omitempty"` // Base64 encoded
	Message   string `json:"message,omitempty"`
}

// VerifyRequest represents a verification request
type VerifyRequest struct {
	Data      string `json:"data"`      // Base64 encoded
	Signature string `json:"signature"` // Base64 encoded
}

// VerifyResponse represents a verification response
type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

// Sign signs data using the specified key
func (c *Client) Sign(ctx context.Context, keyID string, data []byte) (*SignResponse, error) {
	req := SignRequest{
		Data: base64.StdEncoding.EncodeToString(data),
	}

	path := fmt.Sprintf("/v1/key/%s/sign", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var signResp SignResponse
	if err := c.parseResponse(resp, &signResp); err != nil {
		return nil, err
	}

	return &signResp, nil
}

// Verify verifies a signature using the specified key
func (c *Client) Verify(ctx context.Context, keyID string, data, signature []byte) (*VerifyResponse, error) {
	req := VerifyRequest{
		Data:      base64.StdEncoding.EncodeToString(data),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	path := fmt.Sprintf("/v1/key/%s/verify", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var verifyResp VerifyResponse
	if err := c.parseResponse(resp, &verifyResp); err != nil {
		return nil, err
	}

	return &verifyResp, nil
}

// HMACRequest represents an HMAC request
type HMACRequest struct {
	Data string `json:"data"` // Base64 encoded
}

// HMACResponse represents an HMAC response
type HMACResponse struct {
	MAC     string `json:"mac,omitempty"` // Base64 encoded
	Message string `json:"message,omitempty"`
}

// HMAC computes HMAC using the specified key
func (c *Client) HMAC(ctx context.Context, keyID string, data []byte) (*HMACResponse, error) {
	req := HMACRequest{
		Data: base64.StdEncoding.EncodeToString(data),
	}

	path := fmt.Sprintf("/v1/key/%s/hmac", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var hmacResp HMACResponse
	if err := c.parseResponse(resp, &hmacResp); err != nil {
		return nil, err
	}

	return &hmacResp, nil
}

// GetRandomResponse represents a random generation response
type GetRandomResponse struct {
	Bytes   int    `json:"bytes"`
	Random  string `json:"random,omitempty"` // Base64 encoded
	Message string `json:"message,omitempty"`
}

// GetRandom generates random bytes
func (c *Client) GetRandom(ctx context.Context, n int) ([]byte, error) {
	path := fmt.Sprintf("/v1/random?bytes=%d", n)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, nil, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var randomResp GetRandomResponse
	if parseErr := c.parseResponse(resp, &randomResp); parseErr != nil {
		return nil, parseErr
	}

	if randomResp.Random == "" {
		return nil, fmt.Errorf("no random data in response")
	}

	random, err := base64.StdEncoding.DecodeString(randomResp.Random)
	if err != nil {
		return nil, fmt.Errorf("failed to decode random data: %w", err)
	}

	return random, nil
}

// RewrapRequest represents a rewrap request
type RewrapRequest struct {
	Ciphertext string `json:"ciphertext"`    // Base64 encoded
	Nonce      string `json:"nonce"`         // Base64 encoded
	AAD        string `json:"aad,omitempty"` // Base64 encoded
	OldVersion uint64 `json:"old_version,omitempty"`
}

// RewrapResponse represents a rewrap response
type RewrapResponse struct {
	Ciphertext string `json:"ciphertext,omitempty"` // Base64 encoded
	Nonce      string `json:"nonce,omitempty"`      // Base64 encoded
	Message    string `json:"message,omitempty"`
}

// Rewrap re-encrypts ciphertext with a new key version
//
//nolint:lll // function signature requires multiple parameters
func (c *Client) Rewrap(ctx context.Context, keyID string, ciphertext, nonce, aad []byte, oldVersion uint64) (*RewrapResponse, error) {
	req := RewrapRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
	}

	if len(aad) > 0 {
		req.AAD = base64.StdEncoding.EncodeToString(aad)
	}

	if oldVersion > 0 {
		req.OldVersion = oldVersion
	}

	path := fmt.Sprintf("/v1/key/%s/rewrap", keyID)
	resp, err := c.doRequestWithRetry(ctx, "POST", path, req, defaultMaxRetries)
	if err != nil {
		return nil, err
	}

	var rewrapResp RewrapResponse
	if err := c.parseResponse(resp, &rewrapResp); err != nil {
		return nil, err
	}

	return &rewrapResp, nil
}
