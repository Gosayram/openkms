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

// Package authn provides authentication context management for storing and retrieving identity information.
package authn

import (
	"context"
)

type contextKey string

const identityKey contextKey = "identity"

// WithIdentity adds identity to context
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

// GetIdentity retrieves identity from context
func GetIdentity(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityKey).(*Identity)
	return identity, ok
}

// MustGetIdentity retrieves identity from context or panics
func MustGetIdentity(ctx context.Context) *Identity {
	identity, ok := GetIdentity(ctx)
	if !ok {
		panic("identity not found in context")
	}
	return identity
}
