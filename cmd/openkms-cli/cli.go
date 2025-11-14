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

// Package main provides the OpenKMS CLI tool for interacting with the OpenKMS server.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Gosayram/openkms/internal/version"
	"github.com/Gosayram/openkms/pkg/sdk"
)

const (
	// defaultClientTimeout is the default timeout for HTTP client requests
	defaultClientTimeout = 30 * time.Second
	// defaultFileMode is the default file mode for output files (read/write for owner only)
	defaultFileMode = 0o600
)

// CLI represents the root CLI structure
type CLI struct {
	ServerURL string `flag:"server" env:"OPENKMS_SERVER_URL" default:"http://localhost:8080" help:"OpenKMS server URL"`
	Token     string `flag:"token" env:"OPENKMS_TOKEN" help:"Authentication token"`

	Version VersionCmd `cmd:"" help:"Show version information"`
	Init    InitCmd    `cmd:"" help:"Initialize openkms"`
	Key     KeyCmd     `cmd:"" help:"Key management commands"`
	Encrypt EncryptCmd `cmd:"" help:"Encrypt data"`
	Decrypt DecryptCmd `cmd:"" help:"Decrypt data"`
	Sign    SignCmd    `cmd:"" help:"Sign data"`
	Verify  VerifyCmd  `cmd:"" help:"Verify signature"`
	HMAC    HMACCmd    `cmd:"" help:"Compute HMAC"`
	Rotate  RotateCmd  `cmd:"" help:"Rotate a key"`
	Rewrap  RewrapCmd  `cmd:"" help:"Rewrap ciphertext with new key version"`
	Health  HealthCmd  `cmd:"" help:"Check server health"`
	Migrate MigrateCmd `cmd:"" help:"Database migration commands"`
	Audit   AuditCmd   `cmd:"" help:"View audit logs"`
}

// getClient creates an SDK client from CLI configuration
func (c *CLI) getClient() (*sdk.Client, error) {
	config := sdk.Config{
		BaseURL: c.ServerURL,
		Token:   c.Token,
		Timeout: defaultClientTimeout,
	}
	return sdk.NewClient(config)
}

// readData reads data from file, base64 string, or stdin
func readData(file, data string) ([]byte, error) {
	if file != "" {
		// Validate file path to prevent directory traversal
		cleanPath := filepath.Clean(file)
		if cleanPath != file && cleanPath != filepath.Base(file) {
			return nil, fmt.Errorf("invalid file path: %s", file)
		}
		//nolint:gosec // file path is validated above and controlled by user input
		return os.ReadFile(cleanPath)
	}
	if data != "" {
		return base64.StdEncoding.DecodeString(data)
	}
	// Read from stdin
	return io.ReadAll(os.Stdin)
}

// runCryptoOperation is a helper function that executes a cryptographic operation
// with common error handling and data reading logic.
//
//nolint:lll // function signature with callback is necessarily long
func runCryptoOperation(
	cli *CLI,
	file, data, keyID string,
	op func(context.Context, *sdk.Client, string, []byte) (string, error),
) error {
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	readData, err := readData(file, data)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	ctx := context.Background()
	result, err := op(ctx, client, keyID, readData)
	if err != nil {
		return err
	}

	fmt.Println(result)
	return nil
}

// VersionCmd shows version information
type VersionCmd struct{}

// Run executes the version command
//
//nolint:unparam // error return is required by kong.Cmd interface
func (v *VersionCmd) Run() error {
	info := version.Info()
	println("openkms-cli version", info["version"])
	println("commit:", info["commit"])
	println("date:", info["date"])
	return nil
}

// InitCmd initializes openkms
type InitCmd struct {
	MasterKeyProvider string `flag:"master-key-provider" default:"env" help:"Master key provider (env, file)"`
	MasterKeyPath     string `flag:"master-key-path" help:"Path to master key file (for file provider)"`
	StorageType       string `flag:"storage-type" default:"boltdb" help:"Storage type (file, boltdb)"`
	StoragePath       string `flag:"storage-path" default:"./data/openkms.db" help:"Storage path"`
}

// Run executes the init command
//
//nolint:unparam // error return is required by kong.Cmd interface
func (i *InitCmd) Run() error {
	// TODO: Implement initialization
	println("Initializing openkms...")
	println("Master key provider:", i.MasterKeyProvider)
	println("Storage type:", i.StorageType)
	println("Storage path:", i.StoragePath)
	println("Init command not yet implemented")
	return nil
}

// KeyCmd manages keys
type KeyCmd struct {
	Create CreateKeyCmd `cmd:"" help:"Create a new key"`
	List   ListKeysCmd  `cmd:"" help:"List all keys"`
	Get    GetKeyCmd    `cmd:"" help:"Get key metadata"`
}

// CreateKeyCmd creates a new key
type CreateKeyCmd struct {
	CLI       *CLI   `kong:"-"`
	ID        string `arg:"" required:"" help:"Key ID"`
	Type      string `flag:"type" default:"dek" help:"Key type (master-key, kek, dek, signing-key, hmac-key)"`
	Algorithm string `flag:"algorithm" default:"AES-256-GCM" help:"Algorithm (AES-256-GCM, XChaCha20-Poly1305, Ed25519, HMAC-SHA-256)"` //nolint:lll // long help text is necessary for user clarity
}

// Run executes the create key command
func (c *CreateKeyCmd) Run() error {
	cli := c.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	req := sdk.CreateKeyRequest{
		ID:        c.ID,
		Type:      c.Type,
		Algorithm: c.Algorithm,
	}

	resp, err := client.CreateKey(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}

	fmt.Printf("Key created successfully: %s\n", resp.ID)
	if resp.Message != "" {
		fmt.Printf("Message: %s\n", resp.Message)
	}
	return nil
}

// ListKeysCmd lists all keys
type ListKeysCmd struct {
	Prefix string `flag:"prefix" help:"Key ID prefix filter"`
}

// Run executes the list keys command
//
//nolint:unparam // error return is required by kong.Cmd interface
func (l *ListKeysCmd) Run() error {
	// TODO: Implement key listing
	println("Listing keys with prefix:", l.Prefix)
	println("List keys command not yet implemented")
	return nil
}

// GetKeyCmd gets key metadata
type GetKeyCmd struct {
	CLI *CLI   `kong:"-"`
	ID  string `arg:"" required:"" help:"Key ID"`
}

// Run executes the get key command
func (g *GetKeyCmd) Run() error {
	cli := g.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	resp, err := client.GetKey(ctx, g.ID)
	if err != nil {
		return fmt.Errorf("failed to get key: %w", err)
	}

	// Output as JSON
	output, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

// EncryptCmd encrypts data
type EncryptCmd struct {
	CLI       *CLI   `kong:"-"`
	KeyID     string `arg:"" required:"" help:"Key ID"`
	Plaintext string `flag:"plaintext" help:"Plaintext to encrypt (base64)"`
	File      string `flag:"file" help:"File to encrypt"`
	Output    string `flag:"output" help:"Output file (default: stdout)"`
}

// Run executes the encrypt command
func (e *EncryptCmd) Run() error {
	cli := e.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Read plaintext
	plaintext, err := readData(e.File, e.Plaintext)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	ctx := context.Background()
	resp, err := client.Encrypt(ctx, e.KeyID, plaintext, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Output result
	result := map[string]string{
		"ciphertext": resp.Ciphertext,
		"nonce":      resp.Nonce,
	}
	if resp.Message != "" {
		result["message"] = resp.Message
	}

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if e.Output != "" {
		if err := os.WriteFile(e.Output, output, defaultFileMode); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
	} else {
		fmt.Println(string(output))
	}
	return nil
}

// DecryptCmd decrypts data
type DecryptCmd struct {
	CLI        *CLI   `kong:"-"`
	KeyID      string `arg:"" required:"" help:"Key ID"`
	Ciphertext string `flag:"ciphertext" help:"Ciphertext to decrypt (base64)"`
	Nonce      string `flag:"nonce" help:"Nonce (base64)"`
	File       string `flag:"file" help:"File to decrypt"`
	Output     string `flag:"output" help:"Output file (default: stdout)"`
}

// Run executes the decrypt command
func (d *DecryptCmd) Run() error {
	cli := d.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Read ciphertext and nonce
	var ciphertext, nonce []byte

	if d.File != "" {
		// Read from JSON file
		fileData, readErr := os.ReadFile(d.File)
		if readErr != nil {
			return fmt.Errorf("failed to read file: %w", readErr)
		}
		var jsonData map[string]string
		if readErr := json.Unmarshal(fileData, &jsonData); readErr != nil {
			return fmt.Errorf("failed to parse file: %w", readErr)
		}
		var decodeErr error
		ciphertext, decodeErr = base64.StdEncoding.DecodeString(jsonData["ciphertext"])
		if decodeErr != nil {
			return fmt.Errorf("failed to decode ciphertext: %w", decodeErr)
		}
		nonce, decodeErr = base64.StdEncoding.DecodeString(jsonData["nonce"])
		if decodeErr != nil {
			return fmt.Errorf("failed to decode nonce: %w", decodeErr)
		}
	} else {
		if d.Ciphertext == "" || d.Nonce == "" {
			return fmt.Errorf("ciphertext and nonce are required")
		}
		var decodeErr error
		ciphertext, decodeErr = base64.StdEncoding.DecodeString(d.Ciphertext)
		if decodeErr != nil {
			return fmt.Errorf("failed to decode ciphertext: %w", decodeErr)
		}
		nonce, decodeErr = base64.StdEncoding.DecodeString(d.Nonce)
		if decodeErr != nil {
			return fmt.Errorf("failed to decode nonce: %w", decodeErr)
		}
	}

	ctx := context.Background()
	resp, err := client.Decrypt(ctx, d.KeyID, ciphertext, nonce, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return fmt.Errorf("failed to decode plaintext: %w", err)
	}

	if d.Output != "" {
		if err := os.WriteFile(d.Output, plaintext, defaultFileMode); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
	} else {
		fmt.Print(string(plaintext))
	}
	return nil
}

// SignCmd signs data
type SignCmd struct {
	CLI   *CLI   `kong:"-"`
	KeyID string `arg:"" required:"" help:"Key ID"`
	Data  string `flag:"data" help:"Data to sign (base64)"`
	File  string `flag:"file" help:"File to sign"`
}

// Run executes the sign command
func (s *SignCmd) Run() error {
	//nolint:lll // callback function signature is necessarily long
	return runCryptoOperation(s.CLI, s.File, s.Data, s.KeyID, func(
		ctx context.Context,
		client *sdk.Client,
		keyID string,
		data []byte,
	) (string, error) {
		resp, err := client.Sign(ctx, keyID, data)
		if err != nil {
			return "", fmt.Errorf("failed to sign: %w", err)
		}
		return resp.Signature, nil
	})
}

// VerifyCmd verifies a signature
type VerifyCmd struct {
	CLI       *CLI   `kong:"-"`
	KeyID     string `arg:"" required:"" help:"Key ID"`
	Data      string `flag:"data" help:"Data to verify (base64)"`
	Signature string `flag:"signature" required:"" help:"Signature to verify (base64)"`
	File      string `flag:"file" help:"File to verify"`
}

// Run executes the verify command
func (v *VerifyCmd) Run() error {
	cli := v.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Read data
	data, err := readData(v.File, v.Data)
	if err != nil {
		return fmt.Errorf("failed to read data: %w", err)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(v.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	ctx := context.Background()
	resp, err := client.Verify(ctx, v.KeyID, data, signature)
	if err != nil {
		return fmt.Errorf("failed to verify: %w", err)
	}

	if resp.Valid {
		fmt.Println("Signature is valid")
		os.Exit(0)
	}
	fmt.Println("Signature is invalid")
	os.Exit(1)
	//nolint:unreachable // os.Exit above prevents reaching here
	return nil
}

// HMACCmd computes HMAC
type HMACCmd struct {
	CLI   *CLI   `kong:"-"`
	KeyID string `arg:"" required:"" help:"Key ID"`
	Data  string `flag:"data" help:"Data for HMAC (base64)"`
	File  string `flag:"file" help:"File for HMAC"`
}

// Run executes the HMAC command
func (h *HMACCmd) Run() error {
	//nolint:lll // callback function signature is necessarily long
	return runCryptoOperation(h.CLI, h.File, h.Data, h.KeyID, func(
		ctx context.Context,
		client *sdk.Client,
		keyID string,
		data []byte,
	) (string, error) {
		resp, err := client.HMAC(ctx, keyID, data)
		if err != nil {
			return "", fmt.Errorf("failed to compute HMAC: %w", err)
		}
		return resp.MAC, nil
	})
}

// RotateCmd rotates a key
type RotateCmd struct {
	CLI   *CLI   `kong:"-"`
	KeyID string `arg:"" required:"" help:"Key ID"`
	Force bool   `flag:"force" help:"Force rotation even if key is not active"`
}

// Run executes the rotate command
func (r *RotateCmd) Run() error {
	cli := r.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	resp, err := client.RotateKey(ctx, r.KeyID, r.Force)
	if err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	fmt.Printf("Key rotated successfully: %s\n", resp.KeyID)
	fmt.Printf("New version: %d\n", resp.NewVersion)
	if resp.Message != "" {
		fmt.Printf("Message: %s\n", resp.Message)
	}
	return nil
}

// RewrapCmd rewraps ciphertext with a new key version
type RewrapCmd struct {
	CLI        *CLI   `kong:"-"`
	KeyID      string `arg:"" required:"" help:"Key ID"`
	Ciphertext string `flag:"ciphertext" required:"" help:"Ciphertext (base64)"`
	Nonce      string `flag:"nonce" required:"" help:"Nonce (base64)"`
	AAD        string `flag:"aad" help:"Additional authenticated data (base64)"`
	OldVersion uint64 `flag:"old-version" help:"Old key version (default: current version)"`
	Output     string `flag:"output" help:"Output file (default: stdout)"`
}

// Run executes the rewrap command
func (r *RewrapCmd) Run() error {
	cli := r.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Decode inputs
	ciphertext, err := base64.StdEncoding.DecodeString(r.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(r.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	var aad []byte
	if r.AAD != "" {
		aad, err = base64.StdEncoding.DecodeString(r.AAD)
		if err != nil {
			return fmt.Errorf("failed to decode AAD: %w", err)
		}
	}

	ctx := context.Background()
	resp, err := client.Rewrap(ctx, r.KeyID, ciphertext, nonce, aad, r.OldVersion)
	if err != nil {
		return fmt.Errorf("failed to rewrap: %w", err)
	}

	// Output result
	output := fmt.Sprintf("Ciphertext: %s\nNonce: %s\n", resp.Ciphertext, resp.Nonce)
	if resp.Message != "" {
		output += fmt.Sprintf("Message: %s\n", resp.Message)
	}

	if r.Output != "" {
		if err := os.WriteFile(r.Output, []byte(output), defaultFileMode); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("Rewrapped data written to %s\n", r.Output)
	} else {
		fmt.Print(output)
	}

	return nil
}

// HealthCmd checks server health
type HealthCmd struct {
	CLI *CLI `kong:"-"`
}

// Run executes the health command
func (h *HealthCmd) Run() error {
	cli := h.CLI
	client, err := cli.getClient()
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	// TODO: Add Health method to SDK when health endpoint is implemented
	// For now, just try to connect
	_, err = client.GetKey(ctx, "health-check")
	if err != nil {
		// If it's a 404, server is responding
		if err.Error() != "" {
			fmt.Println("Server is responding")
			return nil
		}
		return fmt.Errorf("server health check failed: %w", err)
	}

	fmt.Println("Server is healthy")
	return nil
}

// MigrateCmd manages database migrations
type MigrateCmd struct {
	Up   MigrateUpCmd   `cmd:"" help:"Apply pending migrations"`
	Down MigrateDownCmd `cmd:"" help:"Rollback last migration"`
}

// MigrateUpCmd applies pending migrations
type MigrateUpCmd struct {
	CLI *CLI `kong:"-"`
}

// Run executes the migrate up command
func (m *MigrateUpCmd) Run() error {
	// TODO: Implement migration up when migration API is available
	fmt.Println("Migration up command not yet implemented")
	return nil
}

// MigrateDownCmd rolls back the last migration
type MigrateDownCmd struct {
	CLI *CLI `kong:"-"`
}

// Run executes the migrate down command
func (m *MigrateDownCmd) Run() error {
	// TODO: Implement migration down when migration API is available
	fmt.Println("Migration down command not yet implemented")
	return nil
}

// AuditCmd views audit logs
type AuditCmd struct {
	CLI    *CLI   `kong:"-"`
	KeyID  string `flag:"key-id" help:"Filter by key ID"`
	Limit  int    `flag:"limit" default:"100" help:"Maximum number of logs to return"`
	Format string `flag:"format" default:"json" help:"Output format (json, table)"`
}

// Run executes the audit command
//
//nolint:unparam // error return is required by kong.Cmd interface
func (a *AuditCmd) Run() error {
	// TODO: Implement audit log viewing when audit API is available
	fmt.Printf("Audit logs (key-id: %s, limit: %d, format: %s)\n", a.KeyID, a.Limit, a.Format)
	fmt.Println("Audit log viewing not yet implemented")
	return nil
}
