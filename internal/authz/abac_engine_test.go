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

func TestABACEngine_CheckAccess(t *testing.T) {
	engine := NewABACEngine()

	// Test 1: No policies - should deny by default
	attrs := Attributes{
		Subject: SubjectAttributes{ID: "user1"},
		Object:  ObjectAttributes{ID: "key1"},
		Action:  "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny by default, got allow")
	}

	// Test 2: Add allow policy
	engine.AddPolicy(ABACPolicy{
		Name:     "allow-encrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Action == "encrypt" && attrs.Subject.ID == "user1"
		},
	})

	allowed, err = engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow, got deny")
	}

	// Test 3: Different user - should deny
	attrs.Subject.ID = "user2"
	allowed, err = engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for different user, got allow")
	}
}

func TestABACEngine_Priority(t *testing.T) {
	engine := NewABACEngine()

	// Add deny policy with higher priority
	engine.AddPolicy(ABACPolicy{
		Name:     "deny-all",
		Effect:   "deny",
		Priority: 10,
		Condition: func(Attributes) bool {
			return true
		},
	})

	// Add allow policy with lower priority
	engine.AddPolicy(ABACPolicy{
		Name:     "allow-encrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Action == "encrypt"
		},
	})

	// Higher priority deny should win
	attrs := Attributes{
		Subject: SubjectAttributes{ID: "user1"},
		Object:  ObjectAttributes{ID: "key1"},
		Action:  "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny (higher priority), got allow")
	}
}

func TestABACEngine_TenantIsolation(t *testing.T) {
	engine := NewABACEngine()

	// Add policy: allow if tenant matches
	engine.AddPolicy(ABACPolicy{
		Name:     "tenant-isolation",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Subject.Tenant != "" &&
				attrs.Object.Tenant != "" &&
				attrs.Subject.Tenant == attrs.Object.Tenant
		},
	})

	// Test: same tenant - should allow
	attrs := Attributes{
		Subject: SubjectAttributes{
			ID:     "user1",
			Tenant: "tenant1",
		},
		Object: ObjectAttributes{
			ID:     "key1",
			Tenant: "tenant1",
		},
		Action: "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for same tenant, got deny")
	}

	// Test: different tenant - should deny
	attrs.Object.Tenant = "tenant2"
	allowed, err = engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for different tenant, got allow")
	}
}

func TestABACEngine_StateBasedAccess(t *testing.T) {
	engine := NewABACEngine()

	// Add policy: only allow operations on active keys
	engine.AddPolicy(ABACPolicy{
		Name:     "active-keys-only",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Object.State == "active"
		},
	})

	// Test: active key - should allow
	attrs := Attributes{
		Subject: SubjectAttributes{ID: "user1"},
		Object: ObjectAttributes{
			ID:    "key1",
			State: "active",
		},
		Action: "encrypt",
	}
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow for active key, got deny")
	}

	// Test: disabled key - should deny
	attrs.Object.State = "disabled"
	allowed, err = engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny for disabled key, got allow")
	}
}

func TestABACEngine_EnableDisable(t *testing.T) {
	engine := NewABACEngine()

	// Add policy
	engine.AddPolicy(ABACPolicy{
		Name:     "allow-all",
		Effect:   "allow",
		Priority: 1,
		Condition: func(Attributes) bool {
			return true
		},
	})

	attrs := Attributes{
		Subject: SubjectAttributes{ID: "user1"},
		Object:  ObjectAttributes{ID: "key1"},
		Action:  "encrypt",
	}

	// Should allow when enabled
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow when enabled, got deny")
	}

	// Disable engine
	engine.Disable()
	if engine.IsEnabled() {
		t.Error("Expected engine to be disabled")
	}

	// Should error when disabled
	_, err = engine.CheckAccess(&attrs)
	if err == nil {
		t.Error("Expected error when engine is disabled")
	}

	// Re-enable
	engine.Enable()
	if !engine.IsEnabled() {
		t.Error("Expected engine to be enabled")
	}

	// Should allow again
	allowed, err = engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow when re-enabled, got deny")
	}
}

func TestABACEngine_RemovePolicy(t *testing.T) {
	engine := NewABACEngine()

	// Add policy
	engine.AddPolicy(ABACPolicy{
		Name:     "allow-encrypt",
		Effect:   "allow",
		Priority: 1,
		Condition: func(attrs Attributes) bool {
			return attrs.Action == "encrypt"
		},
	})

	attrs := Attributes{
		Subject: SubjectAttributes{ID: "user1"},
		Object:  ObjectAttributes{ID: "key1"},
		Action:  "encrypt",
	}

	// Should allow
	allowed, err := engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Expected allow, got deny")
	}

	// Remove policy
	engine.RemovePolicy("allow-encrypt")

	// Should deny
	allowed, err = engine.CheckAccess(&attrs)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("Expected deny after removing policy, got allow")
	}
}

func TestBuildCondition(t *testing.T) {
	// Test tenant matching condition
	condition := BuildCondition("subject.tenant == object.tenant")

	attrs := Attributes{
		Subject: SubjectAttributes{Tenant: "tenant1"},
		Object:  ObjectAttributes{Tenant: "tenant1"},
	}
	if !condition(attrs) {
		t.Error("Expected condition to match for same tenant")
	}

	attrs.Object.Tenant = "tenant2"
	if condition(attrs) {
		t.Error("Expected condition to not match for different tenant")
	}

	// Test state condition
	condition = BuildCondition("object.state == 'active'")
	attrs = Attributes{
		Object: ObjectAttributes{State: "active"},
	}
	if !condition(attrs) {
		t.Error("Expected condition to match for active state")
	}

	attrs.Object.State = "disabled"
	if condition(attrs) {
		t.Error("Expected condition to not match for disabled state")
	}
}
