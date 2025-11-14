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
	"fmt"
	"strings"
)

// Policy defines access policy for an identity
type Policy struct {
	Identity    string
	Permissions PermissionSet
	KeyPatterns []string // Key ID patterns (e.g., "key:*", "key:app-*")
}

// Engine manages authorization policies
// It can use either simple policy engine or Casbin engine
type Engine struct {
	policies  map[string]*Policy
	casbin    *CasbinEngine
	useCasbin bool
}

// IsCasbinEngine returns true if the engine is using Casbin
func (e *Engine) IsCasbinEngine() bool {
	return e.useCasbin && e.casbin != nil
}

// GetCasbinEngine returns the Casbin engine if available
func (e *Engine) GetCasbinEngine() *CasbinEngine {
	if e.useCasbin {
		return e.casbin
	}
	return nil
}

// NewEngine creates a new authorization engine
func NewEngine() *Engine {
	return &Engine{
		policies:  make(map[string]*Policy),
		useCasbin: false,
	}
}

// NewEngineWithCasbin creates a new authorization engine with Casbin
func NewEngineWithCasbin(casbinEngine *CasbinEngine) *Engine {
	return &Engine{
		policies:  make(map[string]*Policy),
		casbin:    casbinEngine,
		useCasbin: true,
	}
}

// AddPolicy adds a policy
func (e *Engine) AddPolicy(policy *Policy) {
	e.policies[policy.Identity] = policy
}

// RemovePolicy removes a policy
func (e *Engine) RemovePolicy(identity string) {
	delete(e.policies, identity)
}

// GetPolicy retrieves a policy for an identity
func (e *Engine) GetPolicy(identity string) (*Policy, bool) {
	policy, ok := e.policies[identity]
	return policy, ok
}

// CheckPermission checks if identity has permission for a key
func (e *Engine) CheckPermission(identity string, permission Permission, keyID string) (bool, error) {
	// Use Casbin if enabled
	if e.useCasbin && e.casbin != nil {
		return e.casbin.CheckPermission(identity, permission, keyID)
	}

	// Fallback to simple policy engine
	policy, ok := e.policies[identity]
	if !ok {
		return false, fmt.Errorf("no policy found for identity: %s", identity)
	}

	// Check if identity has the permission
	if !policy.Permissions.Has(permission) {
		return false, nil
	}

	// Check if key matches any pattern
	if len(policy.KeyPatterns) == 0 {
		// No patterns means access to all keys
		return true, nil
	}

	for _, pattern := range policy.KeyPatterns {
		if matchPattern(keyID, pattern) {
			return true, nil
		}
	}

	return false, nil
}

// matchPattern matches a key ID against a pattern
// Supports wildcards: * matches any sequence, ? matches single character
func matchPattern(keyID, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}

	// Check for exact match
	if keyID == pattern {
		return true
	}

	// Check for prefix match (pattern ends with *)
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(keyID, prefix)
	}

	// Check for suffix match (pattern starts with *)
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(keyID, suffix)
	}

	// Check for contains match (*pattern*)
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		substr := strings.TrimPrefix(strings.TrimSuffix(pattern, "*"), "*")
		return strings.Contains(keyID, substr)
	}

	return false
}

// ListPolicies returns all policies
func (e *Engine) ListPolicies() []*Policy {
	policies := make([]*Policy, 0, len(e.policies))
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}
	return policies
}
