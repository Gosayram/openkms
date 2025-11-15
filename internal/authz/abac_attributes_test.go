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
	"time"

	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/keystore"
)

func TestExtractSubjectAttributes(t *testing.T) {
	tests := []struct {
		name     string
		identity *authn.Identity
		want     SubjectAttributes
	}{
		{
			name: "full metadata",
			identity: &authn.Identity{
				ID:   "user1",
				Type: "token",
				Metadata: map[string]string{
					"tenant":     "tenant1",
					"namespace":  "ns1",
					"role":       "admin",
					"department": "security",
					"team":       "infra",
				},
			},
			want: SubjectAttributes{
				ID:         "user1",
				Type:       "token",
				Tenant:     "tenant1",
				Namespace:  "ns1",
				Role:       "admin",
				Department: "security",
				Team:       "infra",
			},
		},
		{
			name: "minimal metadata",
			identity: &authn.Identity{
				ID:       "user2",
				Type:     "mtls",
				Metadata: map[string]string{},
			},
			want: SubjectAttributes{
				ID:       "user2",
				Type:     "mtls",
				Metadata: map[string]string{},
			},
		},
		{
			name: "nil metadata",
			identity: &authn.Identity{
				ID:       "user3",
				Type:     "oidc",
				Metadata: nil,
			},
			want: SubjectAttributes{
				ID:       "user3",
				Type:     "oidc",
				Metadata: map[string]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSubjectAttributes(tt.identity)

			if got.ID != tt.want.ID {
				t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type = %v, want %v", got.Type, tt.want.Type)
			}
			if got.Tenant != tt.want.Tenant {
				t.Errorf("Tenant = %v, want %v", got.Tenant, tt.want.Tenant)
			}
			if got.Namespace != tt.want.Namespace {
				t.Errorf("Namespace = %v, want %v", got.Namespace, tt.want.Namespace)
			}
			if got.Role != tt.want.Role {
				t.Errorf("Role = %v, want %v", got.Role, tt.want.Role)
			}
		})
	}
}

func TestExtractObjectAttributes(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name        string
		keyMetadata *keystore.KeyMetadata
		want        ObjectAttributes
	}{
		{
			name: "full metadata",
			keyMetadata: &keystore.KeyMetadata{
				ID:        "tenant1:ns1:key1",
				Type:      keystore.KeyTypeDEK,
				Algorithm: keystore.AlgorithmAES256GCM,
				State:     keystore.KeyStateActive,
				Version:   1,
				CreatedAt: now,
			},
			want: ObjectAttributes{
				ID:        "tenant1:ns1:key1",
				Type:      "dek",
				Algorithm: "AES-256-GCM",
				State:     "active",
				Version:   1,
				Metadata:  map[string]string{},
				Tenant:    "tenant1",
				Namespace: "ns1",
			},
		},
		{
			name: "namespace only",
			keyMetadata: &keystore.KeyMetadata{
				ID:        "ns1:key1",
				Type:      keystore.KeyTypeSigning,
				Algorithm: keystore.AlgorithmEd25519,
				State:     keystore.KeyStateActive,
				Version:   1,
			},
			want: ObjectAttributes{
				ID:        "ns1:key1",
				Type:      "signing-key",
				Algorithm: "Ed25519",
				State:     "active",
				Version:   1,
				Metadata:  map[string]string{},
				Namespace: "ns1",
			},
		},
		{
			name: "simple key ID",
			keyMetadata: &keystore.KeyMetadata{
				ID:        "key1",
				Type:      keystore.KeyTypeHMAC,
				Algorithm: keystore.AlgorithmHMACSHA256,
				State:     keystore.KeyStateDeprecated,
				Version:   2,
			},
			want: ObjectAttributes{
				ID:        "key1",
				Type:      "hmac-key",
				Algorithm: "HMAC-SHA-256",
				State:     "deprecated",
				Version:   2,
				Metadata:  map[string]string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractObjectAttributes(tt.keyMetadata)

			if got.ID != tt.want.ID {
				t.Errorf("ID = %v, want %v", got.ID, tt.want.ID)
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type = %v, want %v", got.Type, tt.want.Type)
			}
			if got.Algorithm != tt.want.Algorithm {
				t.Errorf("Algorithm = %v, want %v", got.Algorithm, tt.want.Algorithm)
			}
			if got.State != tt.want.State {
				t.Errorf("State = %v, want %v", got.State, tt.want.State)
			}
			if got.Version != tt.want.Version {
				t.Errorf("Version = %v, want %v", got.Version, tt.want.Version)
			}
			if got.Tenant != tt.want.Tenant {
				t.Errorf("Tenant = %v, want %v", got.Tenant, tt.want.Tenant)
			}
			if got.Namespace != tt.want.Namespace {
				t.Errorf("Namespace = %v, want %v", got.Namespace, tt.want.Namespace)
			}
		})
	}
}

func TestSplitKeyID(t *testing.T) {
	tests := []struct {
		name  string
		keyID string
		want  []string
	}{
		{
			name:  "tenant:namespace:key",
			keyID: "tenant1:ns1:key1",
			want:  []string{"tenant1", "ns1", "key1"},
		},
		{
			name:  "namespace:key",
			keyID: "ns1:key1",
			want:  []string{"ns1", "key1"},
		},
		{
			name:  "simple key",
			keyID: "key1",
			want:  []string{"key1"},
		},
		{
			name:  "empty",
			keyID: "",
			want:  []string{},
		},
		{
			name:  "multiple colons",
			keyID: "a:b:c:d:e",
			want:  []string{"a", "b", "c", "d", "e"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitKeyID(tt.keyID)

			if len(got) != len(tt.want) {
				t.Errorf("splitKeyID() length = %v, want %v", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitKeyID()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildAttributes(t *testing.T) {
	subjectAttrs := SubjectAttributes{
		ID:       "user1",
		Tenant:   "tenant1",
		Metadata: map[string]string{},
	}
	objectAttrs := ObjectAttributes{
		ID:       "key1",
		Tenant:   "tenant1",
		Metadata: map[string]string{},
	}
	envAttrs := EnvironmentAttributes{
		Time:     time.Now(),
		Metadata: map[string]string{},
	}

	attrs := BuildAttributes(&subjectAttrs, &objectAttrs, "encrypt", &envAttrs)

	if attrs.Subject.ID != "user1" {
		t.Errorf("Subject.ID = %v, want user1", attrs.Subject.ID)
	}
	if attrs.Object.ID != "key1" {
		t.Errorf("Object.ID = %v, want key1", attrs.Object.ID)
	}
	if attrs.Action != "encrypt" {
		t.Errorf("Action = %v, want encrypt", attrs.Action)
	}
}
