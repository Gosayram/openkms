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
	"strings"
)

// ProviderType represents the type of master key provider
type ProviderType string

const (
	// ProviderTypeEnv is environment variable provider (dev only)
	ProviderTypeEnv ProviderType = "env"
	// ProviderTypeFile is sealed file provider
	ProviderTypeFile ProviderType = "file"
	// ProviderTypePKCS11 is PKCS#11 HSM provider
	ProviderTypePKCS11 ProviderType = "pkcs11"
	// ProviderTypeTPM is TPM 2.0 provider
	ProviderTypeTPM ProviderType = "tpm"
)

// Factory creates master key providers based on configuration
type Factory struct{}

// NewFactory creates a new factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateProvider creates a master key provider based on type and configuration
//
//nolint:gocyclo,funlen // switch statement complexity and function length are acceptable for provider factory
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

	case ProviderTypePKCS11:
		libraryPath := config["library_path"]
		if libraryPath == "" {
			return nil, fmt.Errorf("library_path is required for PKCS#11 provider")
		}

		pin := config["pin"]
		if pin == "" {
			// Try to read from environment
			pin = os.Getenv("OPENKMS_HSM_PIN")
			if pin == "" {
				return nil, fmt.Errorf("PIN is required for PKCS#11 provider (set OPENKMS_HSM_PIN or pin in config)")
			}
		}

		keyLabel := config["key_label"]
		if keyLabel == "" {
			keyLabel = "openkms-master-key"
		}

		slotIDStr := config["slot_id"]
		var slotID uint
		if slotIDStr != "" {
			var slotIDInt int
			if _, err := fmt.Sscanf(slotIDStr, "%d", &slotIDInt); err != nil {
				return nil, fmt.Errorf("invalid slot_id: %s", slotIDStr)
			}
			if slotIDInt < 0 {
				return nil, fmt.Errorf("invalid slot_id: must be non-negative, got %d", slotIDInt)
			}
			slotID = uint(slotIDInt)
		}

		tokenLabel := config["token_label"]
		keyID := config["key_id"]

		return NewPKCS11Provider(&PKCS11Config{
			LibraryPath: libraryPath,
			SlotID:      slotID,
			TokenLabel:  tokenLabel,
			PIN:         pin,
			KeyLabel:    keyLabel,
			KeyID:       keyID,
		})

	case ProviderTypeTPM:
		tpmPath := config["tpm_path"]
		keyLabel := config["key_label"]
		if keyLabel == "" {
			keyLabel = "openkms-master-key"
		}

		// Parse PCR selection (comma-separated list of PCR indices)
		var pcrSelection []int
		if pcrStr := config["pcr_selection"]; pcrStr != "" {
			pcrList := strings.Split(pcrStr, ",")
			for _, pcrStr := range pcrList {
				var pcr int
				if _, err := fmt.Sscanf(strings.TrimSpace(pcrStr), "%d", &pcr); err == nil {
					pcrSelection = append(pcrSelection, pcr)
				}
			}
		}

		useSealed := false
		if sealedStr := config["use_sealed"]; sealedStr == "true" {
			useSealed = true
		}

		return NewTPMProvider(&TPMConfig{
			TPMPath:      tpmPath,
			PCRSelection: pcrSelection,
			KeyLabel:     keyLabel,
			UseSealed:    useSealed,
		})

	default:
		return nil, fmt.Errorf("unknown master key provider type: %s", providerType)
	}
}

// InitializeMasterKey initializes a new master key and saves it using the provider
func InitializeMasterKey(ctx context.Context, provider Provider, _ string) error {
	// Check if master key already exists
	// For PKCS#11 and TPM, we skip this check since key is found during provider creation
	// For other providers, check if key exists
	if _, ok := provider.(*PKCS11Provider); !ok {
		if _, ok := provider.(*TPMProvider); !ok {
			if _, err := provider.GetMasterKey(ctx); err == nil {
				return fmt.Errorf("master key already exists")
			}
		}
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

	// For PKCS#11 provider, generate key in HSM
	if pkcs11Provider, ok := provider.(*PKCS11Provider); ok {
		_, err := pkcs11Provider.RotateMasterKey(ctx)
		if err != nil {
			return fmt.Errorf("failed to generate master key in HSM: %w", err)
		}
		fmt.Printf("Master key generated in HSM with label: %s\n", pkcs11Provider.keyLabel)
		return nil
	}

	// For TPM provider, generate key in TPM
	if tpmProvider, ok := provider.(*TPMProvider); ok {
		_, err := tpmProvider.RotateMasterKey(ctx)
		if err != nil {
			return fmt.Errorf("failed to generate master key in TPM: %w", err)
		}
		fmt.Printf("Master key generated in TPM with label: %s\n", tpmProvider.keyLabel)
		return nil
	}

	return fmt.Errorf("provider type does not support initialization")
}
