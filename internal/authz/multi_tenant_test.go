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
	"testing"
)

func TestMultiTenantPolicies(t *testing.T) {
	engine := NewEngine()

	// Create tenant-scoped policies
	policy1 := &Policy{
		Identity:    "user1",
		Tenant:      "tenant1",
		Permissions: NewPermissionSet(PermissionEncrypt, PermissionDecrypt),
		KeyPatterns: []string{"tenant1:*"},
	}

	policy2 := &Policy{
		Identity:    "user1",
		Tenant:      "tenant2",
		Permissions: NewPermissionSet(PermissionView),
		KeyPatterns: []string{"tenant2:*"},
	}

	// Add tenant-scoped policies
	engine.AddPolicy(policy1)
	engine.AddPolicy(policy2)

	// Test: user1 in tenant1 should have encrypt permission for tenant1 keys
	allowed, err := engine.CheckPermission("user1", PermissionEncrypt, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for user1 in tenant1 to encrypt tenant1 keys")
	}

	// Test: user1 in tenant1 should NOT have encrypt permission for tenant2 keys
	allowed, err = engine.CheckPermission("user1", PermissionEncrypt, "tenant2:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for user1 in tenant1 to encrypt tenant2 keys")
	}

	// Test: user1 in tenant2 should have view permission for tenant2 keys
	allowed, err = engine.CheckPermission("user1", PermissionView, "tenant2:key1", "tenant2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for user1 in tenant2 to view tenant2 keys")
	}

	// Test: user1 in tenant2 should NOT have encrypt permission
	allowed, err = engine.CheckPermission("user1", PermissionEncrypt, "tenant2:key1", "tenant2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for user1 in tenant2 to encrypt (only view allowed)")
	}
}

func TestTenantIsolation(t *testing.T) {
	engine := NewEngine()

	// Create policies for different tenants
	tenant1Policy := &Policy{
		Identity:    "admin",
		Tenant:      "tenant1",
		Permissions: NewPermissionSet(PermissionManage),
		KeyPatterns: []string{"*"},
	}

	tenant2Policy := &Policy{
		Identity:    "admin",
		Tenant:      "tenant2",
		Permissions: NewPermissionSet(PermissionView),
		KeyPatterns: []string{"tenant2:*"},
	}

	engine.AddPolicy(tenant1Policy)
	engine.AddPolicy(tenant2Policy)

	// Test: admin in tenant1 should have manage permission
	allowed, err := engine.CheckPermission("admin", PermissionManage, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for admin in tenant1 to manage keys")
	}

	// Test: admin in tenant2 should NOT have manage permission (only view)
	allowed, err = engine.CheckPermission("admin", PermissionManage, "tenant2:key1", "tenant2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for admin in tenant2 to manage keys (only view allowed)")
	}

	// Test: admin in tenant2 should have view permission
	allowed, err = engine.CheckPermission("admin", PermissionView, "tenant2:key1", "tenant2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for admin in tenant2 to view keys")
	}
}

func TestTenantPolicyManagement(t *testing.T) {
	engine := NewEngine()

	// Test AddTenantPolicy
	policy := &Policy{
		Identity:    "user1",
		Permissions: NewPermissionSet(PermissionEncrypt),
		KeyPatterns: []string{"*"},
	}
	engine.AddTenantPolicy("tenant1", policy)

	// Test GetTenantPolicy
	retrieved, ok := engine.GetTenantPolicy("tenant1", "user1")
	if !ok {
		t.Fatal("Expected to find tenant policy")
	}
	if retrieved.Tenant != "tenant1" {
		t.Errorf("Expected tenant tenant1, got %s", retrieved.Tenant)
	}
	if retrieved.Identity != "user1" {
		t.Errorf("Expected identity user1, got %s", retrieved.Identity)
	}

	// Test ListTenantPolicies
	policies := engine.ListTenantPolicies("tenant1")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	// Test RemoveTenantPolicy
	engine.RemoveTenantPolicy("tenant1", "user1")
	_, ok = engine.GetTenantPolicy("tenant1", "user1")
	if ok {
		t.Error("Expected policy to be removed")
	}
}

func TestGlobalVsTenantPolicies(t *testing.T) {
	engine := NewEngine()

	// Create global policy
	globalPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "",
		Permissions: NewPermissionSet(PermissionView),
		KeyPatterns: []string{"*"},
	}

	// Create tenant-scoped policy
	tenantPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "tenant1",
		Permissions: NewPermissionSet(PermissionEncrypt, PermissionDecrypt),
		KeyPatterns: []string{"tenant1:*"},
	}

	engine.AddPolicy(globalPolicy)
	engine.AddPolicy(tenantPolicy)

	// Test: tenant-scoped policy should take precedence
	allowed, err := engine.CheckPermission("user1", PermissionEncrypt, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for tenant-scoped policy")
	}

	// Test: without tenant, should use global policy
	allowed, err = engine.CheckPermission("user1", PermissionView, "any:key1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for global policy")
	}

	// Test: global policy should not grant encrypt
	allowed, err = engine.CheckPermission("user1", PermissionEncrypt, "any:key1")
	if err == nil {
		// Global policy doesn't have encrypt, should deny
		if allowed {
			t.Error("Expected deny for global policy without encrypt permission")
		}
	}
}

func TestABACTenantIsolation(t *testing.T) {
	engine := NewABACEngine()
	engine.EnableTenantIsolation()

	// Add tenant-scoped ABAC policy
	policy1 := ABACPolicy{
		Name:     "tenant1-encrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Subject.Tenant == "tenant1" && attrs.Action == "encrypt"
		},
	}
	engine.AddTenantPolicy("tenant1", policy1)

	// Add another tenant-scoped policy
	policy2 := ABACPolicy{
		Name:     "tenant2-view",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Subject.Tenant == "tenant2" && attrs.Action == "view"
		},
	}
	engine.AddTenantPolicy("tenant2", policy2)

	// Test: tenant1 user should be able to encrypt
	attrs1 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for tenant1 user to encrypt")
	}

	// Test: tenant1 user should NOT be able to view (no policy for that)
	attrs2 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "view",
	}
	allowed, err = engine.CheckAccess(&attrs2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for tenant1 user to view (no policy)")
	}

	// Test: tenant2 user should be able to view
	attrs3 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user2",
			Tenant: "tenant2",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "view",
	}
	allowed, err = engine.CheckAccess(&attrs3)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for tenant2 user to view")
	}

	// Test: tenant2 user should NOT be able to encrypt
	attrs4 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user2",
			Tenant: "tenant2",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "encrypt",
	}
	allowed, err = engine.CheckAccess(&attrs4)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for tenant2 user to encrypt (no policy)")
	}
}

func TestABACTenantPolicyManagement(t *testing.T) {
	engine := NewABACEngine()
	engine.EnableTenantIsolation()

	// Add tenant policy
	policy := ABACPolicy{
		Name:     "test-policy",
		Effect:   "allow",
		Priority: 1,
		Condition: func(Attributes) bool {
			return true
		},
	}
	engine.AddTenantPolicy("tenant1", policy)

	// Test GetTenantPolicies
	policies := engine.GetTenantPolicies("tenant1")
	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	// Test RemoveTenantPolicy
	engine.RemoveTenantPolicy("tenant1", "test-policy")
	policies = engine.GetTenantPolicies("tenant1")
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies after removal, got %d", len(policies))
	}
}

func TestPolicyInheritance_RBAC(t *testing.T) {
	engine := NewEngine()

	// Create global policy with view and encrypt permissions
	globalPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "",
		Permissions: NewPermissionSet(PermissionView, PermissionEncrypt),
		KeyPatterns: []string{"global:*"},
	}

	// Create tenant-scoped policy with only decrypt permission
	tenantPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "tenant1",
		Permissions: NewPermissionSet(PermissionDecrypt),
		KeyPatterns: []string{"tenant1:*"},
	}

	engine.AddPolicy(globalPolicy)
	engine.AddPolicy(tenantPolicy)

	// Test: tenant policy should inherit view permission from global
	allowed, err := engine.CheckPermission("user1", PermissionView, "global:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for view permission inherited from global policy")
	}

	// Test: tenant policy should inherit encrypt permission from global
	allowed, err = engine.CheckPermission("user1", PermissionEncrypt, "global:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for encrypt permission inherited from global policy")
	}

	// Test: tenant policy should have its own decrypt permission
	allowed, err = engine.CheckPermission("user1", PermissionDecrypt, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for decrypt permission from tenant policy")
	}

	// Test: tenant policy should have access to both global and tenant key patterns
	allowed, err = engine.CheckPermission("user1", PermissionView, "global:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for global key pattern")
	}

	allowed, err = engine.CheckPermission("user1", PermissionView, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for tenant key pattern")
	}

	// Test: permission not in either policy should be denied
	allowed, err = engine.CheckPermission("user1", PermissionDelete, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for delete permission not in any policy")
	}
}

func TestPolicyInheritance_RBAC_KeyPatterns(t *testing.T) {
	engine := NewEngine()

	// Create global policy with all keys pattern
	globalPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "",
		Permissions: NewPermissionSet(PermissionView),
		KeyPatterns: []string{"*"}, // All keys
	}

	// Create tenant-scoped policy with specific pattern
	tenantPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "tenant1",
		Permissions: NewPermissionSet(PermissionView),
		KeyPatterns: []string{"tenant1:*"}, // Only tenant1 keys
	}

	engine.AddPolicy(globalPolicy)
	engine.AddPolicy(tenantPolicy)

	// Test: tenant policy should have access to tenant1 keys (from tenant pattern)
	allowed, err := engine.CheckPermission("user1", PermissionView, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for tenant1 key pattern")
	}

	// Test: tenant policy should also have access to other keys (from global pattern)
	// Since we merge patterns, both global and tenant patterns should be available
	allowed, err = engine.CheckPermission("user1", PermissionView, "other:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for other keys from global pattern (inherited)")
	}
}

func TestPolicyInheritance_RBAC_OnlyTenantPolicy(t *testing.T) {
	engine := NewEngine()

	// Create only tenant-scoped policy (no global)
	tenantPolicy := &Policy{
		Identity:    "user1",
		Tenant:      "tenant1",
		Permissions: NewPermissionSet(PermissionView, PermissionEncrypt),
		KeyPatterns: []string{"tenant1:*"},
	}

	engine.AddPolicy(tenantPolicy)

	// Test: should work with tenant policy only
	allowed, err := engine.CheckPermission("user1", PermissionView, "tenant1:key1", "tenant1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for tenant policy only")
	}

	// Test: should not work without tenant
	_, err = engine.CheckPermission("user1", PermissionView, "tenant1:key1")
	if err == nil {
		t.Error("Expected error when no global policy exists")
	}
}

func TestPolicyInheritance_ABAC(t *testing.T) {
	engine := NewABACEngine()
	// Tenant isolation is disabled by default, so inheritance should work

	// Create global ABAC policy
	globalPolicy := ABACPolicy{
		Name:     "global-encrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Action == "encrypt"
		},
	}
	engine.AddPolicy(globalPolicy)

	// Create tenant-scoped ABAC policy
	tenantPolicy := ABACPolicy{
		Name:     "tenant-decrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Subject.Tenant == "tenant1" && attrs.Action == "decrypt"
		},
	}
	engine.AddTenantPolicy("tenant1", tenantPolicy)

	// Test: tenant user should be able to encrypt (inherited from global)
	attrs1 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for encrypt action inherited from global policy")
	}

	// Test: tenant user should be able to decrypt (from tenant policy)
	attrs2 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "decrypt",
	}
	allowed, err = engine.CheckAccess(&attrs2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for decrypt action from tenant policy")
	}

	// Test: action not in any policy should be denied
	attrs3 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "delete",
	}
	allowed, err = engine.CheckAccess(&attrs3)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for delete action not in any policy")
	}
}

func TestPolicyInheritance_ABAC_WithTenantIsolation(t *testing.T) {
	engine := NewABACEngine()
	engine.EnableTenantIsolation()
	// With tenant isolation enabled, inheritance should NOT work

	// Create global ABAC policy
	globalPolicy := ABACPolicy{
		Name:     "global-encrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Action == "encrypt"
		},
	}
	engine.AddPolicy(globalPolicy)

	// Create tenant-scoped ABAC policy
	tenantPolicy := ABACPolicy{
		Name:     "tenant-decrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Subject.Tenant == "tenant1" && attrs.Action == "decrypt"
		},
	}
	engine.AddTenantPolicy("tenant1", tenantPolicy)

	// Test: tenant user should NOT be able to encrypt (inheritance disabled)
	attrs1 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for encrypt action when tenant isolation is enabled (no inheritance)")
	}

	// Test: tenant user should be able to decrypt (from tenant policy)
	attrs2 := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "decrypt",
	}
	allowed, err = engine.CheckAccess(&attrs2)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for decrypt action from tenant policy")
	}
}

func TestPolicyInheritance_ABAC_Priority(t *testing.T) {
	engine := NewABACEngine()
	// Tenant isolation is disabled by default

	// Create global policy with lower priority
	globalPolicy := ABACPolicy{
		Name:     "global-allow",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Action == "encrypt"
		},
	}
	engine.AddPolicy(globalPolicy)

	// Create tenant-scoped policy with higher priority that denies
	tenantPolicy := ABACPolicy{
		Name:     "tenant-deny",
		Effect:   "deny",
		Priority: 10, // Higher priority
		Condition: func(attrs Attributes) bool {
			return attrs.Subject.Tenant == "tenant1" && attrs.Action == "encrypt"
		},
	}
	engine.AddTenantPolicy("tenant1", tenantPolicy)

	// Test: tenant user should be denied (tenant policy has higher priority)
	attrs := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{ID: "key1"},
		Action: "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for encrypt action (tenant deny policy has higher priority)")
	}
}
