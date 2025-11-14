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

package masterkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// ProviderType represents the type of master key provider
type ProviderType string

const (
	// ProviderTypeEnv is environment variable provider (dev only)
	ProviderTypeEnv ProviderType = "env"
	// ProviderTypeFile is sealed file provider
	ProviderTypeFile ProviderType = "file"
)

// Factory creates master key providers based on configuration
type Factory struct{}

// NewFactory creates a new factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateProvider creates a master key provider based on type and configuration
func (f *Factory) CreateProvider(providerType string, config map[string]string) (Provider, error) {
	switch ProviderType(providerType) {
	case ProviderTypeEnv:
		envVar := config["env_var"]
		if envVar == "" {
			envVar = "OPENKMS_MASTER_KEY"
		}
		return NewEnvProvider(envVar), nil

	case ProviderTypeFile:
		filePath := config["file_path"]
		if filePath == "" {
			return nil, fmt.Errorf("file_path is required for file provider")
		}

		password := config["password"]
		if password == "" {
			// Try to read from environment
			password = os.Getenv("OPENKMS_MASTER_KEY_PASSWORD")
			if password == "" {
				return nil, fmt.Errorf("password is required for file provider (set OPENKMS_MASTER_KEY_PASSWORD)")
			}
		}

		return NewFileProvider(filePath, []byte(password)), nil

	default:
		return nil, fmt.Errorf("unknown master key provider type: %s", providerType)
	}
}

// InitializeMasterKey initializes a new master key and saves it using the provider
func InitializeMasterKey(ctx context.Context, provider Provider, _ string) error {
	// Check if master key already exists
	if _, err := provider.GetMasterKey(ctx); err == nil {
		return fmt.Errorf("master key already exists")
	}

	// Generate new master key
	masterKey := make([]byte, aes256MasterKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// If provider is file-based, save it
	if fileProvider, ok := provider.(*FileProvider); ok {
		if err := fileProvider.SaveMasterKey(masterKey); err != nil {
			return fmt.Errorf("failed to save master key: %w", err)
		}
		return nil
	}

	// For env provider, just print the key (dev only)
	if _, ok := provider.(*EnvProvider); ok {
		fmt.Printf("Generated master key (hex): %s\n", hex.EncodeToString(masterKey))
		fmt.Printf("Set environment variable: export OPENKMS_MASTER_KEY=%s\n", hex.EncodeToString(masterKey))
		return nil
	}

	return fmt.Errorf("provider type does not support initialization")
}
