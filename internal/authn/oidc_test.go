// Copyright 2026 Gosayram Contributors
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

package authn

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCProviderGetCachedToken_ValidEntry(t *testing.T) {
	provider := &OIDCProvider{
		tokenCache: make(map[string]*cachedToken),
	}

	provider.setCachedToken("token", &cachedToken{
		identity:  &Identity{ID: "user-1", Type: "oidc"},
		expiresAt: time.Now().Add(time.Minute),
	})

	cached, ok := provider.getCachedToken("token")
	require.True(t, ok)
	require.NotNil(t, cached)
	assert.Equal(t, "user-1", cached.identity.ID)
}

func TestOIDCProviderGetCachedToken_ExpiredEntryRemoved(t *testing.T) {
	provider := &OIDCProvider{
		tokenCache: make(map[string]*cachedToken),
	}

	provider.setCachedToken("expired", &cachedToken{
		identity:  &Identity{ID: "user-expired", Type: "oidc"},
		expiresAt: time.Now().Add(-time.Minute),
	})

	cached, ok := provider.getCachedToken("expired")
	require.False(t, ok)
	assert.Nil(t, cached)

	provider.mu.RLock()
	_, exists := provider.tokenCache["expired"]
	provider.mu.RUnlock()
	assert.False(t, exists)
}

func TestOIDCProviderValidateToken_UsesValidCache(t *testing.T) {
	provider := &OIDCProvider{
		tokenCache: make(map[string]*cachedToken),
	}

	provider.setCachedToken("cached", &cachedToken{
		identity:  &Identity{ID: "cached-user", Type: "oidc"},
		expiresAt: time.Now().Add(time.Minute),
	})

	err := provider.ValidateToken(context.Background(), "cached")
	require.NoError(t, err)
}

func TestOIDCProviderGetCachedToken_ConcurrentAccess(t *testing.T) {
	provider := &OIDCProvider{
		tokenCache: make(map[string]*cachedToken),
	}

	for i := 0; i < 40; i++ {
		token := fmt.Sprintf("token-%d", i)
		expiresAt := time.Now().Add(time.Minute)
		if i%2 == 0 {
			expiresAt = time.Now().Add(-time.Minute)
		}
		provider.setCachedToken(token, &cachedToken{
			identity:  &Identity{ID: fmt.Sprintf("user-%d", i), Type: "oidc"},
			expiresAt: expiresAt,
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("token-%d", idx%40)
			_, _ = provider.getCachedToken(token)
		}(i)
	}
	wg.Wait()

	provider.mu.RLock()
	defer provider.mu.RUnlock()
	for token, entry := range provider.tokenCache {
		assert.True(t, time.Now().Before(entry.expiresAt), "expired token must be removed: %s", token)
	}
}
