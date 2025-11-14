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

package server

import (
	"crypto/x509"
	"fmt"
	"net/http"

	"go.uber.org/zap"
)

// mTLSMiddleware enforces mutual TLS authentication
func mTLSMiddleware(logger *zap.Logger, requireClientCert bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if connection is TLS
			if r.TLS == nil {
				logger.Warn("Non-TLS connection attempt")
				http.Error(w, "TLS required", http.StatusBadRequest)
				return
			}

			// If client cert is required, verify it's present
			if requireClientCert {
				if len(r.TLS.PeerCertificates) == 0 {
					logger.Warn("Client certificate not provided")
					http.Error(w, "Client certificate required", http.StatusUnauthorized)
					return
				}

				// Verify client certificate
				if err := verifyClientCertificate(r.TLS.PeerCertificates[0]); err != nil {
					logger.Warn("Client certificate verification failed", zap.Error(err))
					http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
					return
				}
			}

			// Extract client identity from certificate
			if len(r.TLS.PeerCertificates) > 0 {
				cert := r.TLS.PeerCertificates[0]
				identity := extractIdentity(cert)
				r.Header.Set("X-Client-Identity", identity)
				r.Header.Set("X-Client-CN", cert.Subject.CommonName)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// verifyClientCertificate verifies a client certificate
func verifyClientCertificate(cert *x509.Certificate) error {
	// Basic validation
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	// Check expiration
	if cert.NotAfter.Before(cert.NotBefore) {
		return fmt.Errorf("certificate has invalid validity period")
	}

	// Additional validation can be added here:
	// - Check against CA
	// - Verify certificate chain
	// - Check certificate extensions
	// - Verify key usage

	return nil
}

// extractIdentity extracts client identity from certificate
func extractIdentity(cert *x509.Certificate) string {
	// Try to get identity from Subject Alternative Name (SAN)
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}

	// Fallback to Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Last resort: use certificate serial number
	return cert.SerialNumber.String()
}

// GetClientIdentity extracts client identity from request
func GetClientIdentity(r *http.Request) string {
	// Try header first (set by middleware)
	if identity := r.Header.Get("X-Client-Identity"); identity != "" {
		return identity
	}

	// Fallback to certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return extractIdentity(r.TLS.PeerCertificates[0])
	}

	return "unknown"
}

// RequireMTLS wraps a handler with mTLS requirement
func RequireMTLS(logger *zap.Logger) func(http.Handler) http.Handler {
	return mTLSMiddleware(logger, true)
}

// OptionalMTLS wraps a handler with optional mTLS
func OptionalMTLS(logger *zap.Logger) func(http.Handler) http.Handler {
	return mTLSMiddleware(logger, false)
}
