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
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
)

// MTLSProvider implements mTLS certificate-based authentication
type MTLSProvider struct{}

// NewMTLSProvider creates a new mTLS authentication provider
func NewMTLSProvider() *MTLSProvider {
	return &MTLSProvider{}
}

// AuthenticateFromRequest authenticates from HTTP request with mTLS
func (m *MTLSProvider) AuthenticateFromRequest(r *http.Request) (*Identity, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("no TLS connection: %w", ErrUnauthorized)
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate: %w", ErrUnauthorized)
	}

	cert := r.TLS.PeerCertificates[0]
	identity := extractIdentityFromCert(cert)

	return &Identity{
		ID:   identity,
		Type: "mtls",
		Metadata: map[string]string{
			"cn":         cert.Subject.CommonName,
			"serial":     cert.SerialNumber.String(),
			"issuer":     cert.Issuer.String(),
			"not_before": cert.NotBefore.Format("2006-01-02T15:04:05Z"),
			"not_after":  cert.NotAfter.Format("2006-01-02T15:04:05Z"),
		},
	}, nil
}

// Authenticate authenticates using token (not applicable for mTLS)
//
//nolint:revive // ctx parameter is required by Provider interface
func (m *MTLSProvider) Authenticate(ctx context.Context, token string) (*Identity, error) {
	// mTLS doesn't use tokens, this is for interface compatibility
	return nil, ErrInvalidToken
}

// ValidateToken validates token (not applicable for mTLS)
//
//nolint:revive // ctx parameter is required by Provider interface
func (m *MTLSProvider) ValidateToken(ctx context.Context, token string) error {
	return ErrInvalidToken
}

// extractIdentityFromCert extracts identity from certificate
func extractIdentityFromCert(cert *x509.Certificate) string {
	// Try Subject Alternative Name (SAN) first
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}

	// Try IP addresses
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}

	// Fallback to Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Last resort: use serial number
	return cert.SerialNumber.String()
}
