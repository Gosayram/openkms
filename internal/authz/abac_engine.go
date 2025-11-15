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
	policies []ABACPolicy
	// Enable ABAC (can be disabled to fall back to RBAC)
	enabled bool
}

// NewABACEngine creates a new ABAC engine
func NewABACEngine() *ABACEngine {
	return &ABACEngine{
		policies: make([]ABACPolicy, 0),
		enabled:  true,
	}
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
func (e *ABACEngine) AddPolicy(policy ABACPolicy) {
	e.policies = append(e.policies, policy)
	// Sort by priority (higher priority first)
	e.sortPolicies()
}

// RemovePolicy removes a policy by name
func (e *ABACEngine) RemovePolicy(name string) {
	for i, policy := range e.policies {
		if policy.Name == name {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return
		}
	}
}

// CheckAccess evaluates access decision based on attributes
// Returns (allowed, error)
func (e *ABACEngine) CheckAccess(attrs Attributes) (bool, error) {
	if !e.enabled {
		return false, fmt.Errorf("ABAC engine is disabled")
	}

	// Evaluate policies in priority order
	for _, policy := range e.policies {
		if policy.Condition(attrs) {
			// Policy matched, return its effect
			return policy.Effect == "allow", nil
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

// GetAllPolicies returns all policies
func (e *ABACEngine) GetAllPolicies() []ABACPolicy {
	return e.policies
}

// ClearPolicies removes all policies
func (e *ABACEngine) ClearPolicies() {
	e.policies = make([]ABACPolicy, 0)
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
