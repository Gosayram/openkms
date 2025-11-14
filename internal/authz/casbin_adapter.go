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

package authz

import (
	"bufio"
	"os"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// FileAdapter is a file-based adapter for Casbin policies
type FileAdapter struct {
	filePath string
}

// NewFileAdapter creates a new file-based adapter
func NewFileAdapter(filePath string) *FileAdapter {
	return &FileAdapter{
		filePath: filePath,
	}
}

// LoadPolicy loads all policy rules from the storage.
func (a *FileAdapter) LoadPolicy(m model.Model) error {
	file, err := os.Open(a.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, return empty policy
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		//nolint:errcheck // LoadPolicyLine errors are non-critical, continue loading other lines
		_ = persist.LoadPolicyLine(line, m)
	}

	return scanner.Err()
}

const (
	// defaultPolicyFileMode is the default file mode for policy files
	defaultPolicyFileMode = 0o600
)

// SavePolicy saves all policy rules to the storage.
func (a *FileAdapter) SavePolicy(m model.Model) error {
	file, err := os.OpenFile(a.filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, defaultPolicyFileMode)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer func() {
		//nolint:errcheck // best effort flush on defer
		_ = writer.Flush()
	}()

	// Write policy rules
	for ptype, ast := range m["p"] {
		for _, rule := range ast.Policy {
			line := ptype + ", " + strings.Join(rule, ", ")
			if _, writeErr := writer.WriteString(line + "\n"); writeErr != nil {
				return writeErr
			}
		}
	}

	// Write role definitions
	for ptype, ast := range m["g"] {
		for _, rule := range ast.Policy {
			line := ptype + ", " + strings.Join(rule, ", ")
			if _, writeErr := writer.WriteString(line + "\n"); writeErr != nil {
				return writeErr
			}
		}
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
// This is a no-op for file adapter as policies are saved via SavePolicy
//
//nolint:revive,gocritic,dupl // parameters are required by persist.Adapter interface, similar structure is intentional
func (a *FileAdapter) AddPolicy(_, _ string, _ []string) error {
	// File adapter doesn't support incremental updates
	// Policies are saved via SavePolicy after all changes
	return nil
}

// RemovePolicy removes a policy rule from the storage.
// This is a no-op for file adapter as policies are saved via SavePolicy
//
//nolint:revive,gocritic,dupl // parameters are required by persist.Adapter interface, similar structure is intentional
func (a *FileAdapter) RemovePolicy(_, _ string, _ []string) error {
	// File adapter doesn't support incremental updates
	// Policies are saved via SavePolicy after all changes
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is a no-op for file adapter as policies are saved via SavePolicy
//
//nolint:revive,gocritic // parameters are required by persist.Adapter interface
func (a *FileAdapter) RemoveFilteredPolicy(_, _ string, _ int, _ ...string) error {
	// File adapter doesn't support incremental updates
	// Policies are saved via SavePolicy after all changes
	return nil
}
