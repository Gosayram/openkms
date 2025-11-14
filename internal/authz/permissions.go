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

// Permission represents a permission
type Permission string

const (
	// PermissionEncrypt allows encryption operations
	PermissionEncrypt Permission = "encrypt"
	// PermissionDecrypt allows decryption operations
	PermissionDecrypt Permission = "decrypt"
	// PermissionSign allows signing operations
	PermissionSign Permission = "sign"
	// PermissionVerify allows signature verification
	PermissionVerify Permission = "verify"
	// PermissionHMAC allows HMAC operations
	PermissionHMAC Permission = "hmac"
	// PermissionRotate allows key rotation
	PermissionRotate Permission = "rotate"
	// PermissionDelete allows key deletion
	PermissionDelete Permission = "delete"
	// PermissionView allows viewing key metadata
	PermissionView Permission = "view"
	// PermissionCreate allows key creation
	PermissionCreate Permission = "create"
	// PermissionRewrap allows ciphertext re-encryption
	PermissionRewrap Permission = "rewrap"
	// PermissionManage allows all management operations
	PermissionManage Permission = "manage"
)

// AllPermissions returns all available permissions
func AllPermissions() []Permission {
	return []Permission{
		PermissionEncrypt,
		PermissionDecrypt,
		PermissionSign,
		PermissionVerify,
		PermissionHMAC,
		PermissionRotate,
		PermissionDelete,
		PermissionView,
		PermissionCreate,
		PermissionRewrap,
		PermissionManage,
	}
}

// PermissionSet represents a set of permissions
type PermissionSet map[Permission]bool

// NewPermissionSet creates a new permission set
func NewPermissionSet(permissions ...Permission) PermissionSet {
	ps := make(PermissionSet)
	for _, p := range permissions {
		ps[p] = true
	}
	return ps
}

// Has checks if permission set has a permission
func (ps PermissionSet) Has(permission Permission) bool {
	// Check for manage permission (grants all)
	if ps[PermissionManage] {
		return true
	}
	return ps[permission]
}

// Add adds a permission to the set
func (ps PermissionSet) Add(permission Permission) {
	ps[permission] = true
}

// Remove removes a permission from the set
func (ps PermissionSet) Remove(permission Permission) {
	delete(ps, permission)
}

// Merge merges another permission set into this one
func (ps PermissionSet) Merge(other PermissionSet) {
	for p := range other {
		ps[p] = true
	}
}
