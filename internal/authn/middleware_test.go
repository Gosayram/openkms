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
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestMiddleware_StrictSPIFFEDisablesTokenFallback(t *testing.T) {
	spiffeProvider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		strict:      true,
	}
	staticProvider := NewStaticProvider()
	staticProvider.AddToken(&StaticToken{
		Token:    "valid-token",
		Identity: "admin",
	})

	manager := NewManager(spiffeProvider, staticProvider)
	handler := RequireAuth(manager, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/key/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestMiddleware_NonStrictSPIFFEAllowsTokenFallback(t *testing.T) {
	spiffeProvider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		strict:      false,
	}
	staticProvider := NewStaticProvider()
	staticProvider.AddToken(&StaticToken{
		Token:    "valid-token",
		Identity: "admin",
	})

	manager := NewManager(spiffeProvider, staticProvider)
	handler := RequireAuth(manager, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := GetIdentity(r.Context())
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if identity.ID != "admin" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/key/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestMiddleware_StrictSPIFFEDisablesMTLSFallback(t *testing.T) {
	spiffeProvider := &SPIFFEProvider{
		trustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		strict:      true,
	}
	manager := NewManager(spiffeProvider, NewMTLSProvider())

	handler := RequireAuth(manager, zap.NewNop())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cert := createTestCertificate(t, "mtls-only.example.org")
	req := httptest.NewRequest(http.MethodGet, "/v1/key/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}
