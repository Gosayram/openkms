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
	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/keystore"
)

// ExtractSubjectAttributes extracts subject attributes from Identity
func ExtractSubjectAttributes(identity *authn.Identity) SubjectAttributes {
	attrs := SubjectAttributes{
		ID:       identity.ID,
		Type:     identity.Type,
		Metadata: make(map[string]string),
	}

	// Copy metadata
	if identity.Metadata != nil {
		for k, v := range identity.Metadata {
			attrs.Metadata[k] = v
		}
	}

	// Extract common attributes from metadata
	if tenant, ok := identity.Metadata["tenant"]; ok {
		attrs.Tenant = tenant
	}
	if namespace, ok := identity.Metadata["namespace"]; ok {
		attrs.Namespace = namespace
	}
	if role, ok := identity.Metadata["role"]; ok {
		attrs.Role = role
	}
	if department, ok := identity.Metadata["department"]; ok {
		attrs.Department = department
	}
	if team, ok := identity.Metadata["team"]; ok {
		attrs.Team = team
	}

	return attrs
}

// ExtractObjectAttributes extracts object attributes from KeyMetadata
func ExtractObjectAttributes(keyMetadata *keystore.KeyMetadata) ObjectAttributes {
	attrs := ObjectAttributes{
		ID:        keyMetadata.ID,
		Type:      string(keyMetadata.Type),
		Algorithm: string(keyMetadata.Algorithm),
		State:     string(keyMetadata.State),
		Version:   keyMetadata.Version,
		Metadata:  make(map[string]string),
	}

	// Extract common attributes from key ID or metadata
	// Key IDs can follow patterns like "tenant:namespace:key-name"
	// or we can extract from metadata if available

	// Try to extract tenant and namespace from key ID
	// Format: "tenant:namespace:key-name" or "namespace:key-name"
	const (
		minPartsForTenant = 3 // tenant:namespace:key-name
		minPartsForNS     = 2 // namespace:key-name
	)
	keyID := keyMetadata.ID
	if keyID != "" {
		parts := splitKeyID(keyID)
		if len(parts) >= minPartsForTenant {
			attrs.Tenant = parts[0]
			attrs.Namespace = parts[1]
		} else if len(parts) == minPartsForNS {
			attrs.Namespace = parts[0]
		}
	}

	return attrs
}

// splitKeyID splits a key ID by colon separator
// Handles patterns like "tenant:namespace:key-name"
func splitKeyID(keyID string) []string {
	parts := make([]string, 0)
	current := ""
	for _, char := range keyID {
		if char == ':' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// BuildAttributes builds Attributes from subject, object, action and environment
func BuildAttributes(
	subjectAttrs *SubjectAttributes,
	objectAttrs *ObjectAttributes,
	action string,
	envAttrs *EnvironmentAttributes,
) Attributes {
	return Attributes{
		Subject:     *subjectAttrs,
		Object:      *objectAttrs,
		Action:      action,
		Environment: *envAttrs,
	}
}
