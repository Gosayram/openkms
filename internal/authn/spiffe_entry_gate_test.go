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

//go:build integration || e2e
// +build integration e2e

package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const entryGateValidToken = "entry-gate-valid-token"

func TestSPIFFEEntryGateIntegration_StrictModeAcceptsValidSVID(t *testing.T) {
	caCert, caKey := createEntryGateCA(t, "entry-gate-ca")
	clientCert := createEntryGateClientCert(t, caCert, caKey, "spiffe://example.org/workload/api")

	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	provider := &SPIFFEProvider{
		trustDomain: trustDomain,
		bundle:      x509bundle.FromX509Authorities(trustDomain, []*x509.Certificate{caCert}),
		strict:      true,
	}

	server := newEntryGateServer(t, NewManager(provider), tls.RequireAndVerifyClientCert, certPool(caCert))
	client := newEntryGateClient(t, server, &clientCert)

	resp, err := client.Get(server.URL + "/v1/spiffe-check")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "spiffe", resp.Header.Get("X-Identity-Type"))
	assert.Equal(t, "spiffe://example.org/workload/api", resp.Header.Get("X-Identity-ID"))
}

func TestSPIFFEEntryGateIntegration_StrictModeRejectsWrongTrustDomain(t *testing.T) {
	caCert, caKey := createEntryGateCA(t, "entry-gate-ca")
	clientCert := createEntryGateClientCert(t, caCert, caKey, "spiffe://other.org/workload/api")

	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	provider := &SPIFFEProvider{
		trustDomain: trustDomain,
		bundle:      x509bundle.FromX509Authorities(trustDomain, []*x509.Certificate{caCert}),
		strict:      true,
	}

	server := newEntryGateServer(t, NewManager(provider), tls.RequireAndVerifyClientCert, certPool(caCert))
	client := newEntryGateClient(t, server, &clientCert)

	resp, err := client.Get(server.URL + "/v1/spiffe-check")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSPIFFEEntryGateIntegration_StrictModeRejectsBundleMismatch(t *testing.T) {
	caForMTLS, caForMTLSKey := createEntryGateCA(t, "entry-gate-mtls-ca")
	clientCert := createEntryGateClientCert(t, caForMTLS, caForMTLSKey, "spiffe://example.org/workload/api")

	caForSPIFFEBundle, _ := createEntryGateCA(t, "entry-gate-spiffe-bundle-ca")
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	provider := &SPIFFEProvider{
		trustDomain: trustDomain,
		bundle:      x509bundle.FromX509Authorities(trustDomain, []*x509.Certificate{caForSPIFFEBundle}),
		strict:      true,
	}

	server := newEntryGateServer(t, NewManager(provider), tls.RequireAndVerifyClientCert, certPool(caForMTLS))
	client := newEntryGateClient(t, server, &clientCert)

	resp, err := client.Get(server.URL + "/v1/spiffe-check")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSPIFFEEntryGateE2E_StrictModeDisablesTokenFallback(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	spiffeProvider := &SPIFFEProvider{
		trustDomain: trustDomain,
		strict:      true,
	}
	staticProvider := newEntryGateStaticProvider()

	server := newEntryGateServer(t, NewManager(spiffeProvider, staticProvider), tls.RequestClientCert, nil)
	client := newEntryGateClient(t, server, nil)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/spiffe-check", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+entryGateValidToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestSPIFFEEntryGateE2E_NonStrictAllowsTokenFallback(t *testing.T) {
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	spiffeProvider := &SPIFFEProvider{
		trustDomain: trustDomain,
		strict:      false,
	}
	staticProvider := newEntryGateStaticProvider()

	server := newEntryGateServer(t, NewManager(spiffeProvider, staticProvider), tls.RequestClientCert, nil)
	client := newEntryGateClient(t, server, nil)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/spiffe-check", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+entryGateValidToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "token", resp.Header.Get("X-Identity-Type"))
	assert.Equal(t, "spiffe-fallback-admin", resp.Header.Get("X-Identity-ID"))
}

func TestSPIFFEEntryGateE2E_mTLSHandshakeRequiresClientCertificate(t *testing.T) {
	caCert, _ := createEntryGateCA(t, "entry-gate-ca")
	trustDomain := spiffeid.RequireTrustDomainFromString("example.org")
	provider := &SPIFFEProvider{
		trustDomain: trustDomain,
		bundle:      x509bundle.FromX509Authorities(trustDomain, []*x509.Certificate{caCert}),
		strict:      true,
	}

	server := newEntryGateServer(t, NewManager(provider), tls.RequireAndVerifyClientCert, certPool(caCert))
	client := newEntryGateClient(t, server, nil)

	_, err := client.Get(server.URL + "/v1/spiffe-check")
	require.Error(t, err)
}

func newEntryGateServer(
	t *testing.T,
	manager *Manager,
	clientAuth tls.ClientAuthType,
	clientCAs *x509.CertPool,
) *httptest.Server {
	t.Helper()

	handler := RequireAuth(manager, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := GetIdentity(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("X-Identity-Type", identity.Type)
		w.Header().Set("X-Identity-ID", identity.ID)
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: clientAuth,
		ClientCAs:  clientCAs,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server
}

func newEntryGateClient(t *testing.T, server *httptest.Server, cert *tls.Certificate) *http.Client {
	t.Helper()

	client := server.Client()
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)

	transportClone := transport.Clone()
	if cert != nil {
		transportClone.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}
	client.Transport = transportClone

	return client
}

func newEntryGateStaticProvider() *StaticProvider {
	staticProvider := NewStaticProvider()
	staticProvider.AddToken(&StaticToken{
		Token:    entryGateValidToken,
		Identity: "spiffe-fallback-admin",
	})

	return staticProvider
}

func certPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func createEntryGateCA(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	return caCert, caKey
}

func createEntryGateClientCert(
	t *testing.T,
	caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
	spiffeURI string,
) tls.Certificate {
	t.Helper()

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "spiffe-client",
		},
		URIs:                  []*url.URL{entryGateMustParseURL(t, spiffeURI)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientDER,
	})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	clientTLSCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)

	return clientTLSCert
}

func entryGateMustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsedURL
}
