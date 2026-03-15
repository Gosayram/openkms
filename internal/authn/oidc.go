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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider implements OIDC/JWT authentication
type OIDCProvider struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	config       *oauth2.Config
	clientID     string
	issuer       string
	userIDClaim  string
	mu           sync.RWMutex
	tokenCache   map[string]*cachedToken
	cacheTimeout time.Duration
}

// cachedToken stores a validated token with expiration
type cachedToken struct {
	identity    *Identity
	expiresAt   time.Time
	validatedAt time.Time
}

// OIDCConfig contains OIDC provider configuration
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	UserIDClaim  string // Claim to use as user ID (default: "sub")
}

const (
	// defaultCacheTimeout is the default cache timeout for validated tokens
	defaultCacheTimeout = 5 * time.Minute
	// stateTokenSize is the size of the random state token in bytes
	stateTokenSize = 32
)

// NewOIDCProvider creates a new OIDC authentication provider
func NewOIDCProvider(ctx context.Context, config *OIDCConfig) (*OIDCProvider, error) {
	if config.Issuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required")
	}
	if config.ClientID == "" {
		return nil, fmt.Errorf("OIDC client ID is required")
	}

	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Create verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.RedirectURL,
		Scopes:       config.Scopes,
	}
	if len(oauth2Config.Scopes) == 0 {
		oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	userIDClaim := config.UserIDClaim
	if userIDClaim == "" {
		userIDClaim = "sub"
	}

	return &OIDCProvider{
		provider:     provider,
		verifier:     verifier,
		config:       oauth2Config,
		clientID:     config.ClientID,
		issuer:       config.Issuer,
		userIDClaim:  userIDClaim,
		tokenCache:   make(map[string]*cachedToken),
		cacheTimeout: defaultCacheTimeout,
	}, nil
}

// Authenticate authenticates a JWT token and returns identity
func (o *OIDCProvider) Authenticate(ctx context.Context, token string) (*Identity, error) {
	// Check cache first
	if cached, ok := o.getCachedToken(token); ok {
		return cached.identity, nil
	}

	// Verify token
	idToken, err := o.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	// Extract user ID
	userID, ok := claims[o.userIDClaim].(string)
	if !ok {
		return nil, fmt.Errorf("user ID claim %q not found or invalid", o.userIDClaim)
	}

	// Build metadata
	metadata := make(map[string]string)
	for key, value := range claims {
		if strValue, ok := value.(string); ok {
			metadata[key] = strValue
		}
	}

	identity := &Identity{
		ID:       userID,
		Type:     "oidc",
		Metadata: metadata,
	}

	// Cache token
	expiresAt := idToken.Expiry
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(o.cacheTimeout)
	}
	o.setCachedToken(token, &cachedToken{
		identity:    identity,
		expiresAt:   expiresAt,
		validatedAt: time.Now(),
	})

	// Cleanup old cache entries periodically
	go o.cleanupCache()

	return identity, nil
}

// ValidateToken validates a JWT token without full authentication
func (o *OIDCProvider) ValidateToken(ctx context.Context, token string) error {
	// Check cache first
	if _, ok := o.getCachedToken(token); ok {
		return nil
	}

	// Verify token
	_, err := o.verifier.Verify(ctx, token)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	return nil
}

// GetAuthURL returns the OAuth2 authorization URL
func (o *OIDCProvider) GetAuthURL(state string) string {
	if state == "" {
		state = generateState()
	}
	return o.config.AuthCodeURL(state)
}

// ExchangeCode exchanges authorization code for token
func (o *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return o.config.Exchange(ctx, code)
}

// GetUserInfo retrieves user information from the OIDC provider
func (o *OIDCProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error) {
	return o.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
}

// cleanupCache removes expired cache entries
func (o *OIDCProvider) cleanupCache() {
	o.mu.Lock()
	defer o.mu.Unlock()

	now := time.Now()
	for token, cached := range o.tokenCache {
		if now.After(cached.expiresAt) {
			delete(o.tokenCache, token)
		}
	}
}

func (o *OIDCProvider) setCachedToken(token string, cached *cachedToken) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tokenCache[token] = cached
}

func (o *OIDCProvider) getCachedToken(token string) (*cachedToken, bool) {
	o.mu.RLock()
	cached, ok := o.tokenCache[token]
	o.mu.RUnlock()
	if !ok {
		return nil, false
	}

	now := time.Now()
	if now.Before(cached.expiresAt) {
		return cached, true
	}

	// Expired entries are removed under write lock to avoid map write under RLock.
	o.mu.Lock()
	defer o.mu.Unlock()
	cached, ok = o.tokenCache[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(cached.expiresAt) {
		delete(o.tokenCache, token)
		return nil, false
	}

	return cached, true
}

// generateState generates a random state string for OAuth2
func generateState() string {
	b := make([]byte, stateTokenSize)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
