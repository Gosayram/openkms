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
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFEProvider implements SPIFFE-based authentication using X.509 SVIDs
type SPIFFEProvider struct {
	trustDomain spiffeid.TrustDomain
	bundle      *x509bundle.Bundle
	strict      bool
}

// SPIFFEConfig holds configuration for SPIFFE authentication
type SPIFFEConfig struct {
	TrustDomain string   `json:"trust_domain" yaml:"trust_domain"`
	BundlePaths []string `json:"bundle_paths" yaml:"bundle_paths"`
	// WorkloadAPI socket path, defaults to default workload API endpoint
	WorkloadSocket string `json:"workload_socket" yaml:"workload_socket"`
	// Strict mode disables non-SPIFFE fallback paths in middleware.
	Strict bool `json:"strict" yaml:"strict"`
}

// NewSPIFFEProvider creates a new SPIFFE authentication provider
func NewSPIFFEProvider(config *SPIFFEConfig) (*SPIFFEProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("SPIFFE config cannot be nil")
	}

	if config.TrustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(config.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain: %w", err)
	}

	provider := &SPIFFEProvider{
		trustDomain: trustDomain,
		strict:      config.Strict,
	}

	// Try to initialize bundle from workload API first
	if config.WorkloadSocket == "" {
		config.WorkloadSocket = "/tmp/spire-agent/public/api.sock"
	}

	ctx := context.Background()
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(config.WorkloadSocket))
	if err == nil {
		defer client.Close()
		bundles, err := client.FetchX509Bundles(ctx)
		if err == nil {
			// Get bundle for our trust domain
			if bundle, ok := bundles.Get(trustDomain); ok {
				provider.bundle = bundle
				return provider, nil
			}
		}
	}

	// Fallback to bundle files if provided
	if len(config.BundlePaths) > 0 {
		for _, bundlePath := range config.BundlePaths {
			bundle, err := x509bundle.Load(trustDomain, bundlePath)
			if err != nil {
				return nil, fmt.Errorf("failed to load bundle from %s: %w", bundlePath, err)
			}
			if bundle.TrustDomain() == trustDomain {
				provider.bundle = bundle
				return provider, nil
			}
		}
		return nil, fmt.Errorf("no bundle found for trust domain %s in provided paths", trustDomain)
	}

	return nil, fmt.Errorf("failed to initialize SPIFFE bundle: no workload API or bundle files available")
}

// AuthenticateFromRequest authenticates from HTTP request with SPIFFE SVID
func (s *SPIFFEProvider) AuthenticateFromRequest(r *http.Request) (*Identity, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("no TLS connection: %w", ErrUnauthorized)
	}

	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate: %w", ErrUnauthorized)
	}

	return s.authenticateFromCertificates(r.TLS.PeerCertificates)
}

// Authenticate authenticates using token (not applicable for SPIFFE)
//
//nolint:revive // ctx parameter is required by Provider interface
func (s *SPIFFEProvider) Authenticate(ctx context.Context, token string) (*Identity, error) {
	// SPIFFE doesn't use tokens, this is for interface compatibility
	return nil, ErrInvalidToken
}

// ValidateToken validates token (not applicable for SPIFFE)
//
//nolint:revive // ctx parameter is required by Provider interface
func (s *SPIFFEProvider) ValidateToken(ctx context.Context, token string) error {
	return ErrInvalidToken
}

// authenticateFromCertificate authenticates using X.509 certificate
func (s *SPIFFEProvider) authenticateFromCertificates(certs []*x509.Certificate) (*Identity, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no client certificate: %w", ErrUnauthorized)
	}

	cert := certs[0]

	// Extract SPIFFE ID from certificate
	spiffeID, err := x509svid.IDFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract SPIFFE ID from certificate: %w", err)
	}

	// Verify the SPIFFE ID belongs to our trust domain
	if spiffeID.TrustDomain() != s.trustDomain {
		return nil, fmt.Errorf("SPIFFE ID trust domain %s does not match expected %s: %w",
			spiffeID.TrustDomain(), s.trustDomain, ErrUnauthorized)
	}

	// Verify certificate chain when trust bundle is available.
	if s.bundle != nil {
		verifyErr := s.verifyCertificateChain(certs)
		if verifyErr != nil {
			return nil, fmt.Errorf("SPIFFE certificate chain verification failed: %w", verifyErr)
		}
	}

	// Extract SPIFFE ID components
	spiffeIDStr := spiffeID.String()

	// Parse the SPIFFE ID to extract components
	idURL, err := url.Parse(spiffeIDStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPIFFE ID: %w", err)
	}

	// Extract path components for metadata
	path := strings.TrimPrefix(idURL.Path, "/")
	pathComponents := strings.Split(path, "/")

	metadata := map[string]string{
		"spiffe_id":    spiffeIDStr,
		"trust_domain": s.trustDomain.String(),
		"serial":       cert.SerialNumber.String(),
		"not_before":   cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		"not_after":    cert.NotAfter.Format("2006-01-02T15:04:05Z"),
	}

	// Add path components to metadata
	for i, component := range pathComponents {
		if component != "" {
			metadata[fmt.Sprintf("path_%d", i)] = component
		}
	}

	// Add certificate subject information
	if cert.Subject.CommonName != "" {
		metadata["cn"] = cert.Subject.CommonName
	}

	// Add organization information
	if len(cert.Subject.Organization) > 0 {
		metadata["organization"] = cert.Subject.Organization[0]
	}

	return &Identity{
		ID:       spiffeIDStr,
		Type:     "spiffe",
		Metadata: metadata,
	}, nil
}

// authenticateFromCertificate authenticates using a leaf X.509 certificate.
// This helper is retained for test compatibility.
func (s *SPIFFEProvider) authenticateFromCertificate(cert *x509.Certificate) (*Identity, error) {
	return s.authenticateFromCertificates([]*x509.Certificate{cert})
}

func (s *SPIFFEProvider) verifyCertificateChain(certs []*x509.Certificate) error {
	roots := x509.NewCertPool()
	for _, authority := range s.bundle.X509Authorities() {
		roots.AddCert(authority)
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}

	return nil
}

// GetTrustDomain returns the configured trust domain
func (s *SPIFFEProvider) GetTrustDomain() spiffeid.TrustDomain {
	return s.trustDomain
}

// IsStrict returns true when provider is configured in strict SPIFFE mode.
func (s *SPIFFEProvider) IsStrict() bool {
	return s.strict
}

// IsWorkloadAPIAvailable checks if workload API is available
func IsWorkloadAPIAvailable(socketPath string) bool {
	if socketPath == "" {
		socketPath = "/tmp/spire-agent/public/api.sock"
	}

	ctx := context.Background()
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return false
	}
	defer client.Close()

	// Try to fetch X509-SVID to verify connectivity
	_, err = client.FetchX509SVID(ctx)
	return err == nil
}
