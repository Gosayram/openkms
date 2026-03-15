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

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestBuildTLSConfigRequiresClientCAPathWhenClientCertIsEnabled(t *testing.T) {
	s := NewServer(&Config{
		RequireClientCert: true,
	}, zap.NewNop())

	_, err := s.buildTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS CA cert file is required")
}

func TestBuildTLSConfigFailsForInvalidClientCAPath(t *testing.T) {
	s := NewServer(&Config{
		RequireClientCert: true,
		TLSCACertFile:     "/path/does/not/exist/ca.pem",
	}, zap.NewNop())

	_, err := s.buildTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read TLS CA cert file")
}

func TestBuildTLSConfigFailsForInvalidClientCAPEM(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "openkms-invalid-ca-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("this-is-not-a-valid-certificate")
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	s := NewServer(&Config{
		RequireClientCert: true,
		TLSCACertFile:     tmpFile.Name(),
	}, zap.NewNop())

	_, err = s.buildTLSConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse any certificates")
}

func TestBuildTLSConfigLoadsClientCAsWhenConfigured(t *testing.T) {
	caPEM := createTestCACertPEM(t)

	tmpFile, err := os.CreateTemp("", "openkms-ca-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.Write(caPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	s := NewServer(&Config{
		RequireClientCert: true,
		TLSCACertFile:     tmpFile.Name(),
	}, zap.NewNop())

	tlsConfig, err := s.buildTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	require.NotNil(t, tlsConfig.ClientCAs)
	assert.NotEmpty(t, tlsConfig.ClientCAs.Subjects())
}

func createTestCACertPEM(t *testing.T) []byte {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openkms-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}
