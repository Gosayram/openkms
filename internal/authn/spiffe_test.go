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

package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPIFFEProvider_NewSPIFFEProvider(t *testing.T) {
	tests := []struct {
		name        string
		config      *SPIFFEConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
			errorMsg:    "SPIFFE config cannot be nil",
		},
		{
			name: "empty trust domain",
			config: &SPIFFEConfig{
				TrustDomain: "",
			},
			expectError: true,
			errorMsg:    "trust domain is required",
		},
		{
			name: "invalid trust domain",
			config: &SPIFFEConfig{
				TrustDomain: "invalid..domain",
			},
			expectError: true,
			errorMsg:    "failed to initialize SPIFFE bundle",
		},
		{
			name: "valid config without bundle",
			config: &SPIFFEConfig{
				TrustDomain: "example.org",
			},
			expectError: true,
			errorMsg:    "failed to initialize SPIFFE bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSPIFFEProvider(tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestSPIFFEProvider_GetTrustDomain(t *testing.T) {
	// Mock the provider creation to avoid bundle initialization
	provider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	
	trustDomain := provider.GetTrustDomain()
	assert.Equal(t, "example.org", trustDomain.String())
}

func TestSPIFFEProvider_Authenticate(t *testing.T) {
	provider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	
	// SPIFFE provider doesn't support token authentication
	identity, err := provider.Authenticate(nil, "some-token")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
	assert.Nil(t, identity)
}

func TestSPIFFEProvider_ValidateToken(t *testing.T) {
	provider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	
	// SPIFFE provider doesn't support token validation
	err := provider.ValidateToken(nil, "some-token")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestSPIFFEProvider_AuthenticateFromRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *http.Request
		expectError bool
		errorMsg    string
	}{
		{
			name:        "no TLS connection",
			request:     &http.Request{},
			expectError: true,
			errorMsg:    "no TLS connection",
		},
		{
			name: "no client certificate",
			request: &http.Request{
				TLS: &tls.ConnectionState{},
			},
			expectError: true,
			errorMsg:    "no client certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &SPIFFEProvider{
				trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
			}
			
			identity, err := provider.AuthenticateFromRequest(tt.request)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, identity)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, identity)
			}
		})
	}
}

func TestSPIFFEProvider_authenticateFromCertificate(t *testing.T) {
	// Create a test certificate with SPIFFE ID
	cert := createTestCertificate(t, "spiffe://example.org/test-service")
	
	provider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	
	identity, err := provider.authenticateFromCertificate(cert)
	assert.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, "spiffe://example.org/test-service", identity.ID)
	assert.Equal(t, "spiffe", identity.Type)
	assert.Contains(t, identity.Metadata, "spiffe_id")
	assert.Equal(t, "spiffe://example.org/test-service", identity.Metadata["spiffe_id"])
	assert.Contains(t, identity.Metadata, "trust_domain")
	assert.Equal(t, "example.org", identity.Metadata["trust_domain"])
}

func TestSPIFFEProvider_authenticateFromCertificate_WrongTrustDomain(t *testing.T) {
	// Create a test certificate with different trust domain
	cert := createTestCertificate(t, "spiffe://other.org/test-service")
	
	provider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	
	identity, err := provider.authenticateFromCertificate(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust domain other.org does not match expected example.org")
	assert.Nil(t, identity)
}

func TestSPIFFEProvider_authenticateFromCertificate_InvalidSPIFFEID(t *testing.T) {
	// Create a test certificate without SPIFFE ID
	cert := createTestCertificate(t, "test-service")
	
	provider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
	}
	
	identity, err := provider.authenticateFromCertificate(cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract SPIFFE ID from certificate")
	assert.Nil(t, identity)
}

func createTestCertificate(t *testing.T, spiffeID string) *x509.Certificate {
	// Generate a test certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: spiffeID,
		},
		URIs:           []*url.URL{mustParseURL(spiffeID)},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	
	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	
	return cert
}

// mustParseURL parses a URL and panics on error
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

func TestIsWorkloadAPIAvailable(t *testing.T) {
	// Test with default socket path (likely not available in test environment)
	available := IsWorkloadAPIAvailable("")
	assert.False(t, available) // Should be false in test environment
	
	// Test with invalid socket path
	available = IsWorkloadAPIAvailable("/invalid/path")
	assert.False(t, available)
}