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

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// CasbinEngine wraps Casbin enforcer for RBAC authorization
type CasbinEngine struct {
	enforcer *casbin.Enforcer
	adapter  persist.Adapter
}

// CasbinConfig contains Casbin configuration
type CasbinConfig struct {
	ModelPath  string // Path to Casbin model file (optional, uses default if empty)
	PolicyPath string // Path to policy file (optional, uses adapter if empty)
	Adapter    persist.Adapter
}

// NewCasbinEngine creates a new Casbin-based authorization engine
func NewCasbinEngine(config CasbinConfig) (*CasbinEngine, error) {
	var m model.Model
	var err error

	// Load model from file or use default
	if config.ModelPath != "" {
		m, err = model.NewModelFromFile(config.ModelPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load Casbin model: %w", err)
		}
	} else {
		// Use default RBAC model
		m = getDefaultRBACModel()
	}

	// Create enforcer
	var enforcer *casbin.Enforcer
	//nolint:gocritic // if-else chain is clearer than switch for this case
	if config.Adapter != nil {
		enforcer, err = casbin.NewEnforcer(m, config.Adapter)
		if err != nil {
			return nil, fmt.Errorf("failed to create Casbin enforcer: %w", err)
		}
	} else if config.PolicyPath != "" {
		enforcer, err = casbin.NewEnforcer(m, config.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create Casbin enforcer: %w", err)
		}
	} else {
		enforcer, err = casbin.NewEnforcer(m)
		if err != nil {
			return nil, fmt.Errorf("failed to create Casbin enforcer: %w", err)
		}
	}

	// Enable auto-save
	enforcer.EnableAutoSave(true)

	return &CasbinEngine{
		enforcer: enforcer,
		adapter:  config.Adapter,
	}, nil
}

// CheckPermission checks if a subject (user/role) has permission for an object (key)
func (c *CasbinEngine) CheckPermission(subject string, permission Permission, object string) (bool, error) {
	// Convert permission to action
	action := ConvertPermissionToAction(permission)

	// Check permission using Casbin
	allowed, err := c.enforcer.Enforce(subject, object, action)
	if err != nil {
		return false, fmt.Errorf("casbin enforce failed: %w", err)
	}

	return allowed, nil
}

// AddPolicy adds a policy rule
func (c *CasbinEngine) AddPolicy(subject, object, action string) (bool, error) {
	return c.enforcer.AddPolicy(subject, object, action)
}

// RemovePolicy removes a policy rule
func (c *CasbinEngine) RemovePolicy(subject, object, action string) (bool, error) {
	return c.enforcer.RemovePolicy(subject, object, action)
}

// AddRoleForUser assigns a role to a user
func (c *CasbinEngine) AddRoleForUser(user, role string) (bool, error) {
	return c.enforcer.AddRoleForUser(user, role)
}

// RemoveRoleForUser removes a role from a user
func (c *CasbinEngine) RemoveRoleForUser(user, role string) (bool, error) {
	return c.enforcer.DeleteRoleForUser(user, role)
}

// GetRolesForUser returns all roles for a user
func (c *CasbinEngine) GetRolesForUser(user string) []string {
	roles, _ := c.enforcer.GetRolesForUser(user)
	return roles
}

// GetUsersForRole returns all users for a role
func (c *CasbinEngine) GetUsersForRole(role string) ([]string, error) {
	return c.enforcer.GetUsersForRole(role)
}

// GetPermissionsForUser returns all permissions for a user
func (c *CasbinEngine) GetPermissionsForUser(user string) [][]string {
	perms, _ := c.enforcer.GetPermissionsForUser(user)
	return perms
}

// GetPermissionsForRole returns all permissions for a role
func (c *CasbinEngine) GetPermissionsForRole(role string) [][]string {
	// Get all users with this role
	users, err := c.enforcer.GetUsersForRole(role)
	if err != nil {
		return [][]string{}
	}

	// Collect all permissions for users with this role
	permissions := make([][]string, 0)
	seen := make(map[string]bool)
	for _, user := range users {
		userPerms, _ := c.enforcer.GetPermissionsForUser(user)
		for _, perm := range userPerms {
			key := strings.Join(perm, ":")
			if !seen[key] {
				permissions = append(permissions, perm)
				seen[key] = true
			}
		}
	}

	return permissions
}

// SavePolicy saves policies to storage
func (c *CasbinEngine) SavePolicy() error {
	return c.enforcer.SavePolicy()
}

// LoadPolicy loads policies from storage
func (c *CasbinEngine) LoadPolicy() error {
	return c.enforcer.LoadPolicy()
}

// GetAllPolicies returns all policies
func (c *CasbinEngine) GetAllPolicies() [][]string {
	policies, _ := c.enforcer.GetPolicy()
	return policies
}

// getDefaultRBACModel returns the default RBAC model for OpenKMS
func getDefaultRBACModel() model.Model {
	// RBAC model with domain support
	// Request: sub, obj, act
	// Policy: sub, obj, act
	// Role: sub, role
	text := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	m, _ := model.NewModelFromString(text)
	return m
}

// ConvertPermissionToAction converts OpenKMS Permission to Casbin action
func ConvertPermissionToAction(permission Permission) string {
	// Map OpenKMS permissions to Casbin actions
	actionMap := map[Permission]string{
		PermissionCreate:  "create",
		PermissionView:    "view",
		PermissionEncrypt: "encrypt",
		PermissionDecrypt: "decrypt",
		PermissionSign:    "sign",
		PermissionVerify:  "verify",
		PermissionHMAC:    "hmac",
		PermissionRotate:  "rotate",
		PermissionDelete:  "delete",
		PermissionRewrap:  "rewrap",
	}

	if action, ok := actionMap[permission]; ok {
		return action
	}

	// Fallback to lowercase permission name
	return strings.ToLower(string(permission))
}
