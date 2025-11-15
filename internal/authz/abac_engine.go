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
	"time"
)

// Policy effect constants
const (
	// EffectAllow represents an allow effect in ABAC policies
	EffectAllow = "allow"
	// EffectDeny represents a deny effect in ABAC policies
	EffectDeny = "deny"
)

// Attributes represents attributes used in ABAC decisions
type Attributes struct {
	// Subject attributes (user/identity attributes)
	Subject SubjectAttributes
	// Object attributes (resource/key attributes)
	Object ObjectAttributes
	// Action (permission/operation)
	Action string
	// Environment attributes (contextual attributes like time, IP, etc.)
	Environment EnvironmentAttributes
}

// SubjectAttributes represents attributes of the subject (user/identity)
type SubjectAttributes struct {
	ID       string
	Type     string
	Metadata map[string]string
	// Common attributes that can be extracted from metadata
	Tenant     string
	Namespace  string
	Role       string
	Department string
	Team       string
}

// ObjectAttributes represents attributes of the object (key/resource)
type ObjectAttributes struct {
	ID        string
	Type      string
	Algorithm string
	State     string
	Version   uint64
	// Additional metadata
	Metadata map[string]string
	// Common attributes
	Tenant    string
	Namespace string
	CreatedBy string
}

// EnvironmentAttributes represents contextual attributes
type EnvironmentAttributes struct {
	Time      time.Time
	IP        string
	UserAgent string
	// Additional context
	Metadata map[string]string
}

// ABACPolicy defines an ABAC policy rule
type ABACPolicy struct {
	// Policy name/ID
	Name string
	// Policy description
	Description string
	// Condition function that evaluates attributes
	Condition func(attrs Attributes) bool
	// Effect: allow or deny
	Effect string
	// Priority: higher priority policies are evaluated first
	Priority int
}

// ABACEngine manages ABAC policies and evaluates access decisions
type ABACEngine struct {
	policies       []ABACPolicy
	tenantPolicies map[string][]ABACPolicy // tenant -> policies
	// Enable ABAC (can be disabled to fall back to RBAC)
	enabled bool
	// Enable tenant isolation (policies are scoped to tenant)
	tenantIsolation bool
}

// NewABACEngine creates a new ABAC engine
func NewABACEngine() *ABACEngine {
	return &ABACEngine{
		policies:        make([]ABACPolicy, 0),
		tenantPolicies:  make(map[string][]ABACPolicy),
		enabled:         true,
		tenantIsolation: false,
	}
}

// EnableTenantIsolation enables tenant isolation for ABAC policies
func (e *ABACEngine) EnableTenantIsolation() {
	e.tenantIsolation = true
}

// DisableTenantIsolation disables tenant isolation for ABAC policies
func (e *ABACEngine) DisableTenantIsolation() {
	e.tenantIsolation = false
}

// IsTenantIsolationEnabled returns true if tenant isolation is enabled
func (e *ABACEngine) IsTenantIsolationEnabled() bool {
	return e.tenantIsolation
}

// Enable enables ABAC engine
func (e *ABACEngine) Enable() {
	e.enabled = true
}

// Disable disables ABAC engine (falls back to RBAC)
func (e *ABACEngine) Disable() {
	e.enabled = false
}

// IsEnabled returns true if ABAC is enabled
func (e *ABACEngine) IsEnabled() bool {
	return e.enabled
}

// AddPolicy adds an ABAC policy
// If tenant is provided and tenant isolation is enabled, adds as tenant-scoped policy
func (e *ABACEngine) AddPolicy(policy ABACPolicy, tenant ...string) {
	if len(tenant) > 0 && tenant[0] != "" && e.tenantIsolation {
		// Add tenant-scoped policy
		if e.tenantPolicies[tenant[0]] == nil {
			e.tenantPolicies[tenant[0]] = make([]ABACPolicy, 0)
		}
		e.tenantPolicies[tenant[0]] = append(e.tenantPolicies[tenant[0]], policy)
		e.sortTenantPolicies(tenant[0])
	} else {
		// Add global policy
		e.policies = append(e.policies, policy)
		e.sortPolicies()
	}
}

// AddTenantPolicy adds a tenant-scoped ABAC policy
func (e *ABACEngine) AddTenantPolicy(tenant string, policy ABACPolicy) {
	e.AddPolicy(policy, tenant)
}

// RemovePolicy removes a policy by name
// If tenant is provided, removes tenant-scoped policy, otherwise removes global policy
func (e *ABACEngine) RemovePolicy(name string, tenant ...string) {
	if len(tenant) > 0 && tenant[0] != "" {
		// Remove tenant-scoped policy
		if policies, ok := e.tenantPolicies[tenant[0]]; ok {
			for i, policy := range policies {
				if policy.Name == name {
					e.tenantPolicies[tenant[0]] = append(policies[:i], policies[i+1:]...)
					if len(e.tenantPolicies[tenant[0]]) == 0 {
						delete(e.tenantPolicies, tenant[0])
					}
					return
				}
			}
		}
	} else {
		// Remove global policy
		for i, policy := range e.policies {
			if policy.Name == name {
				e.policies = append(e.policies[:i], e.policies[i+1:]...)
				return
			}
		}
	}
}

// RemoveTenantPolicy removes a tenant-scoped policy by name
func (e *ABACEngine) RemoveTenantPolicy(tenant, name string) {
	e.RemovePolicy(name, tenant)
}

// CheckAccess evaluates access decision based on attributes
// Returns (allowed, error)
// If tenant isolation is enabled, only evaluates tenant-scoped policies
// Otherwise, evaluates tenant-scoped policies first, then falls back to global policies (inheritance)
func (e *ABACEngine) CheckAccess(attrs *Attributes) (bool, error) {
	if !e.enabled {
		return false, fmt.Errorf("ABAC engine is disabled")
	}

	// If tenant isolation is enabled, check tenant-scoped policies only
	if e.tenantIsolation && attrs.Subject.Tenant != "" {
		if tenantPolicies, ok := e.tenantPolicies[attrs.Subject.Tenant]; ok {
			// Evaluate tenant-scoped policies in priority order
			for _, policy := range tenantPolicies {
				if policy.Condition(*attrs) {
					// Policy matched, return its effect
					return policy.Effect == EffectAllow, nil
				}
			}
		}
		// If tenant isolation is enabled and no tenant policy matched, deny
		return false, nil
	}

	// Tenant isolation is disabled - check tenant-scoped policies first, then global (inheritance)
	if attrs.Subject.Tenant != "" {
		if tenantPolicies, ok := e.tenantPolicies[attrs.Subject.Tenant]; ok {
			// Evaluate tenant-scoped policies in priority order
			for _, policy := range tenantPolicies {
				if policy.Condition(*attrs) {
					// Policy matched, return its effect
					return policy.Effect == EffectAllow, nil
				}
			}
		}
		// If no tenant policy matched, fall through to global policies (inheritance)
	}

	// Evaluate global policies in priority order
	for _, policy := range e.policies {
		if policy.Condition(*attrs) {
			// Policy matched, return its effect
			return policy.Effect == EffectAllow, nil
		}
	}

	// No policy matched, deny by default
	return false, nil
}

// sortPolicies sorts policies by priority (higher priority first)
func (e *ABACEngine) sortPolicies() {
	// Simple insertion sort by priority
	for i := 1; i < len(e.policies); i++ {
		key := e.policies[i]
		j := i - 1
		for j >= 0 && e.policies[j].Priority < key.Priority {
			e.policies[j+1] = e.policies[j]
			j--
		}
		e.policies[j+1] = key
	}
}

// sortTenantPolicies sorts tenant policies by priority (higher priority first)
func (e *ABACEngine) sortTenantPolicies(tenant string) {
	policies := e.tenantPolicies[tenant]
	if policies == nil {
		return
	}
	// Simple insertion sort by priority
	for i := 1; i < len(policies); i++ {
		key := policies[i]
		j := i - 1
		for j >= 0 && policies[j].Priority < key.Priority {
			policies[j+1] = policies[j]
			j--
		}
		policies[j+1] = key
	}
	e.tenantPolicies[tenant] = policies
}

// GetAllPolicies returns all policies
// If tenant is provided, returns tenant-scoped policies, otherwise returns global policies
func (e *ABACEngine) GetAllPolicies(tenant ...string) []ABACPolicy {
	if len(tenant) > 0 && tenant[0] != "" {
		if policies, ok := e.tenantPolicies[tenant[0]]; ok {
			return policies
		}
		return []ABACPolicy{}
	}
	return e.policies
}

// GetTenantPolicies returns all policies for a tenant
func (e *ABACEngine) GetTenantPolicies(tenant string) []ABACPolicy {
	return e.GetAllPolicies(tenant)
}

// ClearPolicies removes all policies
// If tenant is provided, clears tenant-scoped policies, otherwise clears global policies
func (e *ABACEngine) ClearPolicies(tenant ...string) {
	if len(tenant) > 0 && tenant[0] != "" {
		delete(e.tenantPolicies, tenant[0])
	} else {
		e.policies = make([]ABACPolicy, 0)
	}
}

// BuildCondition creates a condition function from a simple expression
// This is a helper for creating common conditions
func BuildCondition(expr string) func(Attributes) bool {
	// Simple condition builder - can be extended with expression parser
	switch expr {
	case "subject.tenant == object.tenant":
		return func(attrs Attributes) bool {
			return attrs.Subject.Tenant != "" &&
				attrs.Object.Tenant != "" &&
				attrs.Subject.Tenant == attrs.Object.Tenant
		}
	case "subject.namespace == object.namespace":
		return func(attrs Attributes) bool {
			return attrs.Subject.Namespace != "" &&
				attrs.Object.Namespace != "" &&
				attrs.Subject.Namespace == attrs.Object.Namespace
		}
	case "object.state == 'active'":
		return func(attrs Attributes) bool {
			return attrs.Object.State == "active"
		}
	case "subject.role == 'admin'":
		return func(attrs Attributes) bool {
			return attrs.Subject.Role == "admin"
		}
	default:
		// Return false for unknown expressions
		return func(Attributes) bool {
			return false
		}
	}
}
