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

// Package config provides configuration loading and management for the OpenKMS application.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultServerPort is the default HTTP server port
	defaultServerPort = 8080
	// defaultReadTimeout is the default read timeout for HTTP server
	defaultReadTimeout = 30 * time.Second
	// defaultWriteTimeout is the default write timeout for HTTP server
	defaultWriteTimeout = 30 * time.Second
	// defaultIdleTimeout is the default idle timeout for HTTP server
	defaultIdleTimeout = 120 * time.Second
	// defaultMetricsPort is the default metrics server port
	defaultMetricsPort = 9090
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig
	Storage  StorageConfig
	Security SecurityConfig
	Logging  LoggingConfig
	Metrics  MetricsConfig
}

// ServerConfig contains server-related configuration
type ServerConfig struct {
	Address           string
	Port              int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	TLSEnabled        bool
	TLSCertFile       string
	TLSKeyFile        string
	TLSCACertFile     string
	RequireClientCert bool
}

// StorageConfig contains storage backend configuration
type StorageConfig struct {
	Type           string        // "file", "boltdb", "postgres", "etcd"
	Path           string        // for file/boltdb
	Connection     string        // for postgres
	Endpoints      []string      // for etcd (comma-separated endpoints)
	DialTimeout    time.Duration // for etcd (default: 5s)
	RequestTimeout time.Duration // for etcd (default: 3s)
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	MasterKeyProvider string // "env", "file", "hsm"
	MasterKeyPath     string
	MasterKeyEnvVar   string
	Auth              AuthConfig
}

// AuthConfig contains authentication configuration
type AuthConfig struct {
	Providers        []string // "static", "mtls", "oidc"
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       []string
	OIDCUserIDClaim  string
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level      string // "debug", "info", "warn", "error"
	Format     string // "json", "text"
	OutputPath string
}

// MetricsConfig contains metrics configuration
type MetricsConfig struct {
	Enabled bool
	Path    string
	Port    int
}

// Load loads configuration from environment variables with defaults
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Address:           getEnv("OPENKMS_SERVER_ADDRESS", "0.0.0.0"),
			Port:              getEnvInt("OPENKMS_SERVER_PORT", defaultServerPort),
			ReadTimeout:       getEnvDuration("OPENKMS_SERVER_READ_TIMEOUT", defaultReadTimeout),
			WriteTimeout:      getEnvDuration("OPENKMS_SERVER_WRITE_TIMEOUT", defaultWriteTimeout),
			IdleTimeout:       getEnvDuration("OPENKMS_SERVER_IDLE_TIMEOUT", defaultIdleTimeout),
			TLSEnabled:        getEnvBool("OPENKMS_TLS_ENABLED", true),
			TLSCertFile:       getEnv("OPENKMS_TLS_CERT_FILE", ""),
			TLSKeyFile:        getEnv("OPENKMS_TLS_KEY_FILE", ""),
			TLSCACertFile:     getEnv("OPENKMS_TLS_CA_CERT_FILE", ""),
			RequireClientCert: getEnvBool("OPENKMS_TLS_REQUIRE_CLIENT_CERT", true),
		},
		Storage: StorageConfig{
			Type:           getEnv("OPENKMS_STORAGE_TYPE", "boltdb"),
			Path:           getEnv("OPENKMS_STORAGE_PATH", "./data/openkms.db"),
			Connection:     getEnv("OPENKMS_STORAGE_CONNECTION", ""),
			Endpoints:      getEnvSlice("OPENKMS_STORAGE_ETCD_ENDPOINTS", []string{"localhost:2379"}),
			DialTimeout:    getEnvDuration("OPENKMS_STORAGE_ETCD_DIAL_TIMEOUT", 5*time.Second),
			RequestTimeout: getEnvDuration("OPENKMS_STORAGE_ETCD_REQUEST_TIMEOUT", 3*time.Second),
		},
		Security: SecurityConfig{
			MasterKeyProvider: getEnv("OPENKMS_MASTER_KEY_PROVIDER", "env"),
			MasterKeyPath:     getEnv("OPENKMS_MASTER_KEY_PATH", ""),
			MasterKeyEnvVar:   getEnv("OPENKMS_MASTER_KEY_ENV_VAR", "OPENKMS_MASTER_KEY"),
			Auth: AuthConfig{
				Providers:        getEnvSlice("OPENKMS_AUTH_PROVIDERS", []string{"static", "mtls"}),
				OIDCIssuer:       getEnv("OPENKMS_OIDC_ISSUER", ""),
				OIDCClientID:     getEnv("OPENKMS_OIDC_CLIENT_ID", ""),
				OIDCClientSecret: getEnv("OPENKMS_OIDC_CLIENT_SECRET", ""),
				OIDCRedirectURL:  getEnv("OPENKMS_OIDC_REDIRECT_URL", ""),
				OIDCScopes:       getEnvSlice("OPENKMS_OIDC_SCOPES", []string{"openid", "profile", "email"}),
				OIDCUserIDClaim:  getEnv("OPENKMS_OIDC_USER_ID_CLAIM", "sub"),
			},
		},
		Logging: LoggingConfig{
			Level:      getEnv("OPENKMS_LOG_LEVEL", "info"),
			Format:     getEnv("OPENKMS_LOG_FORMAT", "json"),
			OutputPath: getEnv("OPENKMS_LOG_OUTPUT", ""),
		},
		Metrics: MetricsConfig{
			Enabled: getEnvBool("OPENKMS_METRICS_ENABLED", true),
			Path:    getEnv("OPENKMS_METRICS_PATH", "/metrics"),
			Port:    getEnvInt("OPENKMS_METRICS_PORT", defaultMetricsPort),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.TLSEnabled {
		if c.Server.TLSCertFile == "" {
			return fmt.Errorf("TLS enabled but cert file not specified")
		}
		if c.Server.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled but key file not specified")
		}
		if c.Server.RequireClientCert && c.Server.TLSCACertFile == "" {
			return fmt.Errorf("client cert required but CA cert file not specified")
		}
	}

	if c.Storage.Type == "" {
		return fmt.Errorf("storage type not specified")
	}

	if c.Storage.Type == "etcd" {
		if len(c.Storage.Endpoints) == 0 {
			return fmt.Errorf("etcd storage type requires at least one endpoint")
		}
	}

	if c.Security.MasterKeyProvider == "" {
		return fmt.Errorf("master key provider not specified")
	}

	return nil
}

// Helper functions for environment variable parsing

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Split by comma
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
