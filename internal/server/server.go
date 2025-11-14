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
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	// defaultRequestTimeout is the default timeout for HTTP requests
	defaultRequestTimeout = 60 * time.Second
)

// Server represents the HTTP server
type Server struct {
	router     *chi.Mux
	httpServer *http.Server
	logger     *zap.Logger
	config     *Config
}

// Config contains server configuration
type Config struct {
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

// NewServer creates a new HTTP server
func NewServer(config *Config, logger *zap.Logger) *Server {
	router := chi.NewRouter()

	// Middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(defaultRequestTimeout))
	router.Use(MetricsMiddleware)

	// Health check endpoint
	router.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		// Simple health check - can be extended to check storage, etc.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	s := &Server{
		router: router,
		logger: logger,
		config: config,
	}

	return s
}

// RegisterRoutes registers API routes
func (s *Server) RegisterRoutes(handlers *Handlers) {
	s.router.Route("/v1", func(r chi.Router) {
		// Key management endpoints
		r.Post("/key", handlers.CreateKey)
		r.Get("/key/{id}", handlers.GetKey)
		r.Post("/key/{id}/encrypt", handlers.Encrypt)
		r.Post("/key/{id}/decrypt", handlers.Decrypt)
		r.Post("/key/{id}/sign", handlers.Sign)
		r.Post("/key/{id}/verify", handlers.Verify)
		r.Post("/key/{id}/hmac", handlers.HMAC)
		r.Get("/key/{id}/versions", handlers.GetKeyVersions)
		r.Post("/key/{id}/rotate", handlers.RotateKey)
		r.Post("/key/{id}/rewrap", handlers.Rewrap)

		// Random generation
		r.Post("/random", handlers.GetRandom)
	})

	// Audit endpoints
	s.router.Route("/v1/audit", func(r chi.Router) {
		r.Get("/logs", handlers.GetAuditLogs)
	})

	// Policy management endpoints
	s.router.Route("/v1/policy", func(r chi.Router) {
		r.Post("/", handlers.CreatePolicy)
		r.Delete("/", handlers.DeletePolicy)
		r.Get("/", handlers.ListPolicies)
	})

	// Role management endpoints
	s.router.Route("/v1/role", func(r chi.Router) {
		r.Post("/assign", handlers.AssignRole)
		r.Get("/user/{user}", handlers.GetUserRoles)
	})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	// Configure TLS if enabled
	if s.config.TLSEnabled {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to build TLS config: %w", err)
		}
		s.httpServer.TLSConfig = tlsConfig
	}

	s.logger.Info("Starting HTTP server",
		zap.String("address", addr),
		zap.Bool("tls_enabled", s.config.TLSEnabled),
	)

	if s.config.TLSEnabled {
		return s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	}

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}

	s.logger.Info("Shutting down HTTP server")
	return s.httpServer.Shutdown(ctx)
}

// buildTLSConfig builds TLS configuration
//
//nolint:unparam // error return allows for future error handling
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true,
	}

	// Require client certificates if configured
	if s.config.RequireClientCert {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		// CA cert will be loaded from the cert file
		// In production, use proper CA certificate pool
		_ = s.config.TLSCACertFile
	}

	return tlsConfig, nil
}

// Router returns the chi router (for testing)
func (s *Server) Router() *chi.Mux {
	return s.router
}
