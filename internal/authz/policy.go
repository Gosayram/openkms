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
	Tenant      string // Tenant ID for multi-tenant isolation (empty means global policy)
	Permissions PermissionSet
	KeyPatterns []string // Key ID patterns (e.g., "key:*", "key:app-*")
}

// Engine manages authorization policies
// It can use either simple policy engine, Casbin engine, or ABAC engine
type Engine struct {
	policies  map[string]*Policy // Key: identity or "tenant:identity" for tenant-scoped policies
	casbin    *CasbinEngine
	useCasbin bool
	abac      *ABACEngine
	useABAC   bool
	// Multi-tenant support
	tenantPolicies map[string]map[string]*Policy // tenant -> identity -> policy
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
		policies:       make(map[string]*Policy),
		tenantPolicies: make(map[string]map[string]*Policy),
		useCasbin:      false,
		useABAC:        false,
	}
}

// NewEngineWithCasbin creates a new authorization engine with Casbin
func NewEngineWithCasbin(casbinEngine *CasbinEngine) *Engine {
	return &Engine{
		policies:       make(map[string]*Policy),
		tenantPolicies: make(map[string]map[string]*Policy),
		casbin:         casbinEngine,
		useCasbin:      true,
		useABAC:        false,
	}
}

// NewEngineWithABAC creates a new authorization engine with ABAC
func NewEngineWithABAC(abacEngine *ABACEngine) *Engine {
	return &Engine{
		policies:       make(map[string]*Policy),
		tenantPolicies: make(map[string]map[string]*Policy),
		useABAC:        true,
		abac:           abacEngine,
		useCasbin:      false,
	}
}

// NewEngineWithCasbinAndABAC creates a new authorization engine with both Casbin and ABAC
// ABAC is evaluated first, then Casbin if ABAC doesn't match
func NewEngineWithCasbinAndABAC(casbinEngine *CasbinEngine, abacEngine *ABACEngine) *Engine {
	return &Engine{
		policies:       make(map[string]*Policy),
		tenantPolicies: make(map[string]map[string]*Policy),
		casbin:         casbinEngine,
		useCasbin:      true,
		abac:           abacEngine,
		useABAC:        true,
	}
}

// SetABACEngine sets the ABAC engine
func (e *Engine) SetABACEngine(abacEngine *ABACEngine) {
	e.abac = abacEngine
	e.useABAC = abacEngine != nil && abacEngine.IsEnabled()
}

// GetABACEngine returns the ABAC engine if available
func (e *Engine) GetABACEngine() *ABACEngine {
	return e.abac
}

// IsABACEngine returns true if the engine is using ABAC
func (e *Engine) IsABACEngine() bool {
	return e.useABAC && e.abac != nil
}

// AddPolicy adds a policy
// If policy has a tenant, it's stored as tenant-scoped policy
func (e *Engine) AddPolicy(policy *Policy) {
	if policy.Tenant != "" {
		// Tenant-scoped policy
		if e.tenantPolicies[policy.Tenant] == nil {
			e.tenantPolicies[policy.Tenant] = make(map[string]*Policy)
		}
		e.tenantPolicies[policy.Tenant][policy.Identity] = policy
	} else {
		// Global policy
		e.policies[policy.Identity] = policy
	}
}

// RemovePolicy removes a policy
// If tenant is provided, removes tenant-scoped policy, otherwise removes global policy
func (e *Engine) RemovePolicy(identity string, tenant ...string) {
	if len(tenant) > 0 && tenant[0] != "" {
		// Remove tenant-scoped policy
		if tenantPolicies, ok := e.tenantPolicies[tenant[0]]; ok {
			delete(tenantPolicies, identity)
			if len(tenantPolicies) == 0 {
				delete(e.tenantPolicies, tenant[0])
			}
		}
	} else {
		// Remove global policy
		delete(e.policies, identity)
	}
}

// GetPolicy retrieves a policy for an identity
// If tenant is provided, retrieves tenant-scoped policy, otherwise retrieves global policy
func (e *Engine) GetPolicy(identity string, tenant ...string) (*Policy, bool) {
	if len(tenant) > 0 && tenant[0] != "" {
		// Get tenant-scoped policy
		if tenantPolicies, ok := e.tenantPolicies[tenant[0]]; ok {
			policy, ok := tenantPolicies[identity]
			return policy, ok
		}
		return nil, false
	}
	// Get global policy
	policy, ok := e.policies[identity]
	return policy, ok
}

// AddTenantPolicy adds a tenant-scoped policy
func (e *Engine) AddTenantPolicy(tenant string, policy *Policy) {
	policy.Tenant = tenant
	e.AddPolicy(policy)
}

// RemoveTenantPolicy removes a tenant-scoped policy
func (e *Engine) RemoveTenantPolicy(tenant, identity string) {
	e.RemovePolicy(identity, tenant)
}

// GetTenantPolicy retrieves a tenant-scoped policy
func (e *Engine) GetTenantPolicy(tenant, identity string) (*Policy, bool) {
	return e.GetPolicy(identity, tenant)
}

// ListTenantPolicies returns all policies for a tenant
func (e *Engine) ListTenantPolicies(tenant string) []*Policy {
	if tenantPolicies, ok := e.tenantPolicies[tenant]; ok {
		policies := make([]*Policy, 0, len(tenantPolicies))
		for _, policy := range tenantPolicies {
			policies = append(policies, policy)
		}
		return policies
	}
	return []*Policy{}
}

// CheckPermission checks if identity has permission for a key
// This is the legacy method that doesn't use ABAC attributes
// If tenant is provided, checks tenant-scoped policies first, then global policies (inheritance)
func (e *Engine) CheckPermission(identity string, permission Permission, keyID string, tenant ...string) (bool, error) {
	// Use Casbin if enabled
	if e.useCasbin && e.casbin != nil {
		return e.casbin.CheckPermission(identity, permission, keyID)
	}

	// Get effective policy (tenant-scoped with inheritance from global)
	effectivePolicy, err := e.getEffectivePolicy(identity, tenant...)
	if err != nil {
		return false, err
	}

	return e.checkPolicyPermission(effectivePolicy, permission, keyID)
}

// getEffectivePolicy returns the effective policy for an identity, combining tenant-scoped and global policies
// If tenant is provided and tenant-scoped policy exists, it inherits from global policy
// Returns a merged policy that combines permissions and key patterns from both
func (e *Engine) getEffectivePolicy(identity string, tenant ...string) (*Policy, error) {
	var tenantPolicy *Policy
	var globalPolicy *Policy
	var hasTenantPolicy bool

	// Get tenant-scoped policy if tenant is provided
	if len(tenant) > 0 && tenant[0] != "" {
		tenantPolicy, hasTenantPolicy = e.GetTenantPolicy(tenant[0], identity)
	}

	// Get global policy
	globalPolicy, hasGlobalPolicy := e.policies[identity]

	// If neither exists, return error
	if !hasTenantPolicy && !hasGlobalPolicy {
		return nil, fmt.Errorf("no policy found for identity: %s", identity)
	}

	// If only global policy exists, return it
	if !hasTenantPolicy {
		return globalPolicy, nil
	}

	// If only tenant policy exists, return it
	if !hasGlobalPolicy {
		return tenantPolicy, nil
	}

	// Both exist - merge them (tenant policy inherits from global)
	// Create a new policy that combines both
	effectivePolicy := &Policy{
		Identity:    tenantPolicy.Identity,
		Tenant:      tenantPolicy.Tenant,
		Permissions: make(PermissionSet),
		KeyPatterns: make([]string, 0),
	}

	// Merge permissions: start with global, then add/override with tenant
	for perm := range globalPolicy.Permissions {
		effectivePolicy.Permissions[perm] = true
	}
	for perm := range tenantPolicy.Permissions {
		effectivePolicy.Permissions[perm] = true
	}

	// Merge key patterns: combine both sets
	// Start with global patterns, then add tenant patterns
	effectivePolicy.KeyPatterns = append(effectivePolicy.KeyPatterns, globalPolicy.KeyPatterns...)
	effectivePolicy.KeyPatterns = append(effectivePolicy.KeyPatterns, tenantPolicy.KeyPatterns...)

	return effectivePolicy, nil
}

// checkPolicyPermission checks if a policy grants the requested permission
func (e *Engine) checkPolicyPermission(policy *Policy, permission Permission, keyID string) (bool, error) {
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

// CheckPermissionWithAttributes checks if identity has permission for a key using ABAC attributes
// If ABAC is enabled, it evaluates ABAC policies first, then falls back to RBAC
func (e *Engine) CheckPermissionWithAttributes(attrs *Attributes) (bool, error) {
	// If ABAC is enabled, check ABAC policies first
	if e.useABAC && e.abac != nil {
		allowed, err := e.abac.CheckAccess(attrs)
		if err == nil {
			// ABAC decision made, return it
			// If ABAC denies, we can still check RBAC (depending on policy)
			// For now, if ABAC allows, we allow; if ABAC denies, we check RBAC
			if allowed {
				return true, nil
			}
			// ABAC denied, continue to RBAC check
		}
		// If ABAC error, fall through to RBAC
	}

	// Fall back to RBAC (Casbin or simple policy engine)
	if e.useCasbin && e.casbin != nil {
		return e.casbin.CheckPermission(attrs.Subject.ID, Permission(attrs.Action), attrs.Object.ID)
	}

	// Fallback to simple policy engine
	// Get effective policy (tenant-scoped with inheritance from global)
	var tenant string
	if attrs.Subject.Tenant != "" {
		tenant = attrs.Subject.Tenant
	}
	policy, err := e.getEffectivePolicy(attrs.Subject.ID, tenant)
	if err != nil {
		return false, err
	}

	// Check if identity has the permission
	permission := Permission(attrs.Action)
	if !policy.Permissions.Has(permission) {
		return false, nil
	}

	// Check if key matches any pattern
	if len(policy.KeyPatterns) == 0 {
		// No patterns means access to all keys
		return true, nil
	}

	for _, pattern := range policy.KeyPatterns {
		if matchPattern(attrs.Object.ID, pattern) {
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
// If tenant is provided, returns only tenant-scoped policies, otherwise returns global policies
func (e *Engine) ListPolicies(tenant ...string) []*Policy {
	if len(tenant) > 0 && tenant[0] != "" {
		return e.ListTenantPolicies(tenant[0])
	}

	policies := make([]*Policy, 0, len(e.policies))
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}
	return policies
}

// ListAllPolicies returns all policies (both global and tenant-scoped)
func (e *Engine) ListAllPolicies() []*Policy {
	policies := make([]*Policy, 0, len(e.policies))
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}
	for _, tenantPolicies := range e.tenantPolicies {
		for _, policy := range tenantPolicies {
			policies = append(policies, policy)
		}
	}
	return policies
}
