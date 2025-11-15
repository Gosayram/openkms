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

// Utility for signing artifacts using OpenKMS SDK
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Gosayram/openkms/pkg/sdk"
)

const (
	// signatureFileMode is the file mode for signature files (read/write for owner only)
	signatureFileMode = 0o600
)

func main() {
	var (
		keyID  = flag.String("key-id", "", "Key ID for signing (required)")
		file   = flag.String("file", "", "File to sign (required)")
		url    = flag.String("url", "", "OpenKMS server URL (required)")
		token  = flag.String("token", "", "Authentication token (required)")
		output = flag.String("output", "", "Output signature file (default: FILE.sig)")
		help   = flag.Bool("help", false, "Show help")
	)

	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	// Load configuration from flags and environment
	cfg := loadConfig(keyID, file, url, token, output)
	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Sign the artifact
	if err := signArtifact(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ File signed successfully: %s\n", cfg.output)
}

type config struct {
	keyID  string
	file   string
	url    string
	token  string
	output string
}

// loadConfig loads configuration from flags and environment variables
func loadConfig(keyID, file, url, token, output *string) *config {
	cfg := &config{
		keyID: *keyID,
		file:  *file,
		url:   *url,
		token: *token,
	}

	// Use environment variables if flags are not provided
	if cfg.keyID == "" {
		cfg.keyID = os.Getenv("OPENKMS_KEY_ID")
	}
	if cfg.url == "" {
		cfg.url = os.Getenv("OPENKMS_URL")
	}
	if cfg.token == "" {
		cfg.token = os.Getenv("OPENKMS_TOKEN")
	}

	// Determine output file if not specified
	if *output == "" {
		cfg.output = cfg.file + ".sig"
	} else {
		cfg.output = *output
	}

	return cfg
}

// validateConfig validates the configuration
func validateConfig(cfg *config) error {
	if cfg.keyID == "" {
		return fmt.Errorf("KEY_ID not specified. Use -key-id or set OPENKMS_KEY_ID")
	}
	if cfg.file == "" {
		return fmt.Errorf("FILE not specified. Use -file")
	}
	if cfg.url == "" {
		return fmt.Errorf("URL not specified. Use -url or set OPENKMS_URL")
	}
	if cfg.token == "" {
		return fmt.Errorf("TOKEN not specified. Use -token or set OPENKMS_TOKEN")
	}

	// Check if file exists
	if _, err := os.Stat(cfg.file); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", cfg.file)
	}

	return nil
}

// signArtifact signs the artifact using OpenKMS
func signArtifact(cfg *config) error {
	// Create OpenKMS client
	client, err := sdk.NewClient(sdk.Config{
		BaseURL: cfg.url,
		Token:   cfg.token,
	})
	if err != nil {
		return fmt.Errorf("failed to create OpenKMS client: %w", err)
	}

	// Read file
	fileData, err := os.ReadFile(cfg.file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Sign file
	ctx := context.Background()
	fmt.Printf("Signing file: %s\n", cfg.file)
	fmt.Printf("Using key: %s\n", cfg.keyID)
	fmt.Printf("OpenKMS server: %s\n", cfg.url)

	signResp, err := client.Sign(ctx, cfg.keyID, fileData)
	if err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signResp.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create Cosign-compatible signature format
	signatureJSON := createCosignSignature(signature, fileData)

	// Write signature to file
	if err := os.WriteFile(cfg.output, signatureJSON, signatureFileMode); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stdout, `Usage: %s [OPTIONS]

Signs artifacts using OpenKMS SDK.

OPTIONS:
    -key-id KEY_ID          Key ID for signing (required)
    -file FILE              File to sign (required)
    -url URL                OpenKMS server URL (required)
    -token TOKEN            Authentication token (required)
    -output OUTPUT          Output signature file (default: FILE.sig)
    -help                   Show this help

EXAMPLES:
    # Sign a file
    %s -key-id signing-key -file artifact.tar.gz -url https://openkms.example.com -token YOUR_TOKEN

    # Sign a file with output file specified
    %s -key-id signing-key -file artifact.tar.gz -url https://openkms.example.com -token YOUR_TOKEN -output artifact.sig

    # Use environment variables
    export OPENKMS_URL=https://openkms.example.com
    export OPENKMS_TOKEN=YOUR_TOKEN
    export OPENKMS_KEY_ID=signing-key
    %s -file artifact.tar.gz

ENVIRONMENT VARIABLES:
    OPENKMS_URL                  OpenKMS server URL
    OPENKMS_TOKEN                Authentication token
    OPENKMS_KEY_ID               Key ID for signing

`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}

// createCosignSignature creates Cosign-compatible signature format
func createCosignSignature(signature, payload []byte) []byte {
	// Cosign LocalSignedPayload format
	type cosignSignature struct {
		Base64Signature string `json:"base64Signature"`
		Payload         []byte `json:"payload,omitempty"`
	}

	sig := cosignSignature{
		Base64Signature: base64.StdEncoding.EncodeToString(signature),
		Payload:         payload,
	}

	jsonData, err := json.Marshal(sig)
	if err != nil {
		// Fallback: simple base64 signature
		return []byte(base64.StdEncoding.EncodeToString(signature))
	}

	return jsonData
}
