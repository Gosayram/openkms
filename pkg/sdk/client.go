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

// Package sdk provides the OpenKMS client SDK for interacting with the OpenKMS server.
package sdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// defaultClientTimeout is the default timeout for HTTP client requests
	defaultClientTimeout = 30 * time.Second
	// httpStatusBadRequest is the HTTP status code for bad requests
	httpStatusBadRequest = 400
	// defaultMaxRetries is the default number of retries for failed requests
	defaultMaxRetries = 3
)

// Client is the OpenKMS SDK client
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// Config contains client configuration
type Config struct {
	BaseURL    string
	Token      string
	Timeout    time.Duration
	TLSConfig  *tls.Config
	HTTPClient *http.Client
}

// NewClient creates a new OpenKMS client
func NewClient(config Config) (*Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}

	// Create HTTP client
	httpClient := config.HTTPClient
	if httpClient == nil {
		timeout := config.Timeout
		if timeout == 0 {
			timeout = defaultClientTimeout
		}

		transport := &http.Transport{
			TLSClientConfig: config.TLSConfig,
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}
	}

	return &Client{
		baseURL:    config.BaseURL,
		httpClient: httpClient,
		token:      config.Token,
	}, nil
}

// SetToken sets the authentication token
func (c *Client) SetToken(token string) {
	c.token = token
}

// doRequest performs an HTTP request
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication token if available
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// doRequestWithRetry performs a request with retry logic
//
//nolint:lll,unparam // function signature requires multiple parameters; maxRetries parameter allows for future customization
func (c *Client) doRequestWithRetry(ctx context.Context, method, path string, body interface{}, maxRetries int) (*http.Response, error) {
	var lastErr error

	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			// Exponential backoff
			backoff := time.Duration(i) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.doRequest(ctx, method, path, body)
		if err == nil {
			// Check if we should retry based on status code
			if resp.StatusCode < 500 || i == maxRetries {
				return resp, nil
			}
			_ = resp.Body.Close()
		}

		lastErr = err
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}

// parseResponse parses JSON response
func (c *Client) parseResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()

	if resp.StatusCode >= httpStatusBadRequest {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return fmt.Errorf("API error: %s", errResp.Error)
		}
		return fmt.Errorf("HTTP error: %d %s", resp.StatusCode, resp.Status)
	}

	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
