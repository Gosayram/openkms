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

// Package main provides the OpenKMS server application.
//
//nolint:goimports // imports are properly formatted, golangci-lint cache issue
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Gosayram/openkms/internal/audit"
	"github.com/Gosayram/openkms/internal/authn"
	"github.com/Gosayram/openkms/internal/authz"
	"github.com/Gosayram/openkms/internal/config"
	"github.com/Gosayram/openkms/internal/cryptoengine"
	"github.com/Gosayram/openkms/internal/keystore"
	"github.com/Gosayram/openkms/internal/logging"
	"github.com/Gosayram/openkms/internal/policies/masterkey"
	"github.com/Gosayram/openkms/internal/server"
	"github.com/Gosayram/openkms/internal/storage"
	"github.com/Gosayram/openkms/internal/version"
	"go.uber.org/zap"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, logger := initializeConfigAndLogger()
	defer func() {
		_ = logger.Sync() // Ignore sync errors on exit
	}()

	logStartupInfo(logger, cfg)

	components := initializeComponents(ctx, cfg, logger)
	defer components.masterKeyProvider.Close()
	defer components.storageBackend.Close()

	httpServer := setupHTTPServer(cfg, logger, components)
	startAndShutdownServer(httpServer, cfg, logger)
}

// appComponents holds all initialized application components
type appComponents struct {
	masterKeyProvider *masterkey.Manager
	storageBackend    storage.Backend
	keyStore          *keystore.Store
	cryptoEngine      *cryptoengine.CryptoEngine
	authManager       *authn.Manager
	authzEngine       *authz.Engine
	auditLogger       *audit.Logger
}

// initializeConfigAndLogger loads configuration and initializes logger
func initializeConfigAndLogger() (*config.Config, *logging.Logger) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1) //nolint:gocritic // exitAfterDefer - acceptable for configuration errors
	}

	logger, err := logging.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.OutputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	return cfg, logger
}

// logStartupInfo logs server startup information
func logStartupInfo(logger *logging.Logger, cfg *config.Config) {
	info := version.Info()
	logger.Info("Starting openkms-server",
		zap.String("version", info["version"]),
		zap.String("commit", info["commit"]),
		zap.String("date", info["date"]),
		zap.String("address", cfg.Server.Address),
		zap.Int("port", cfg.Server.Port),
	)
}

// initializeComponents initializes all application components
func initializeComponents(ctx context.Context, cfg *config.Config, logger *logging.Logger) *appComponents {
	masterKeyProvider, err := initializeMasterKey(ctx, cfg, logger.Logger)
	if err != nil {
		logger.Fatal("Failed to initialize master key", zap.Error(err))
	}

	storageBackend, err := initializeStorage(cfg, logger.Logger)
	if err != nil {
		logger.Fatal("Failed to initialize storage", zap.Error(err))
	}

	// Use new EnvelopeBackend with provider support (works with both direct and HSM providers)
	envelopeBackend, err := storage.NewEnvelopeBackendWithProvider(storageBackend, masterKeyProvider.GetProvider())
	if err != nil {
		logger.Fatal("Failed to create envelope backend", zap.Error(err))
	}

	keyStore := keystore.NewStore(envelopeBackend)
	cryptoEngine := cryptoengine.NewEngine()
	authManager := initializeAuth(cfg, logger.Logger)
	authzEngine := authz.NewEngine()
	auditLogger, err := audit.NewLogger(logger.Logger)
	if err != nil {
		logger.Fatal("Failed to initialize audit logger", zap.Error(err))
	}

	return &appComponents{
		masterKeyProvider: masterKeyProvider,
		storageBackend:    storageBackend,
		keyStore:          keyStore,
		cryptoEngine:      cryptoEngine,
		authManager:       authManager,
		authzEngine:       authzEngine,
		auditLogger:       auditLogger,
	}
}

// setupHTTPServer configures and sets up the HTTP server
func setupHTTPServer(cfg *config.Config, logger *logging.Logger, components *appComponents) *server.Server {
	serverConfig := &server.Config{
		Address:           cfg.Server.Address,
		Port:              cfg.Server.Port,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		TLSEnabled:        cfg.Server.TLSEnabled,
		TLSCertFile:       cfg.Server.TLSCertFile,
		TLSKeyFile:        cfg.Server.TLSKeyFile,
		TLSCACertFile:     cfg.Server.TLSCACertFile,
		RequireClientCert: cfg.Server.RequireClientCert,
	}

	httpServer := server.NewServer(serverConfig, logger.Logger)
	handlers := server.NewHandlers(
		logger.Logger,
		components.keyStore,
		components.cryptoEngine,
		components.auditLogger,
		components.authzEngine,
	)
	httpServer.RegisterRoutes(handlers)
	setupMiddleware(httpServer, components.authManager, components.authzEngine, components.auditLogger, logger.Logger, cfg)

	return httpServer
}

// startAndShutdownServer starts the server and handles graceful shutdown
func startAndShutdownServer(httpServer *server.Server, cfg *config.Config, logger *logging.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	serverErrChan := make(chan error, 1)
	go func() {
		logger.Info("Server starting...")
		if err := httpServer.Start(); err != nil {
			serverErrChan <- err
		}
	}()

	select {
	case sig := <-sigChan:
		logger.Info("Shutdown signal received", zap.String("signal", sig.String()))
	case err := <-serverErrChan:
		logger.Error("Server error", zap.Error(err))
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.WriteTimeout)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error during server shutdown", zap.Error(err))
	}

	logger.Info("Server stopped")
}

// initializeMasterKey initializes master key provider
func initializeMasterKey(_ context.Context, cfg *config.Config, _ *zap.Logger) (*masterkey.Manager, error) {
	factory := masterkey.NewFactory()

	providerConfig := map[string]string{
		"env_var":      cfg.Security.MasterKeyEnvVar,
		"file_path":    cfg.Security.MasterKeyPath,
		"library_path": cfg.Security.HSMLibraryPath,
		"token_label":  cfg.Security.HSMTokenLabel,
		"key_label":    cfg.Security.HSMKeyLabel,
		"key_id":       cfg.Security.HSMKeyID,
		"tpm_path":     cfg.Security.TPMPath,
	}

	if cfg.Security.HSMSlotID > 0 {
		providerConfig["slot_id"] = fmt.Sprintf("%d", cfg.Security.HSMSlotID)
	}

	// Add TPM PCR selection if specified
	if len(cfg.Security.TPMPCRSelection) > 0 {
		pcrStrs := make([]string, len(cfg.Security.TPMPCRSelection))
		for i, pcr := range cfg.Security.TPMPCRSelection {
			pcrStrs[i] = fmt.Sprintf("%d", pcr)
		}
		providerConfig["pcr_selection"] = strings.Join(pcrStrs, ",")
	}

	if cfg.Security.TPMUseSealed {
		providerConfig["use_sealed"] = "true"
	}

	// Set TPM key_label if TPM provider is used
	if cfg.Security.MasterKeyProvider == "tpm" {
		if cfg.Security.TPMKeyLabel != "" {
			providerConfig["key_label"] = cfg.Security.TPMKeyLabel
		}
	}

	provider, err := factory.CreateProvider(cfg.Security.MasterKeyProvider, providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key provider: %w", err)
	}

	return masterkey.NewManager(provider), nil
}

// initializeStorage initializes storage backend
func initializeStorage(cfg *config.Config, logger *zap.Logger) (storage.Backend, error) {
	switch cfg.Storage.Type {
	case "file":
		logger.Info("Using file storage backend", zap.String("path", cfg.Storage.Path))
		return storage.NewFileBackend(cfg.Storage.Path)

	case "boltdb":
		logger.Info("Using bbolt storage backend", zap.String("path", cfg.Storage.Path))
		return storage.NewBoltBackend(cfg.Storage.Path)

	case "etcd":
		logger.Info("Using etcd storage backend",
			zap.Strings("endpoints", cfg.Storage.Endpoints),
			zap.Duration("dial_timeout", cfg.Storage.DialTimeout),
			zap.Duration("request_timeout", cfg.Storage.RequestTimeout),
		)
		etcdConfig := storage.EtcdConfig{
			Endpoints:      cfg.Storage.Endpoints,
			DialTimeout:    cfg.Storage.DialTimeout,
			RequestTimeout: cfg.Storage.RequestTimeout,
		}
		return storage.NewEtcdBackend(etcdConfig)

	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Storage.Type)
	}
}

// initializeAuth initializes authentication manager
func initializeAuth(cfg *config.Config, logger *zap.Logger) *authn.Manager {
	var providers []authn.Provider

	// Check which providers are enabled
	enabledProviders := make(map[string]bool)
	for _, provider := range cfg.Security.Auth.Providers {
		enabledProviders[provider] = true
	}

	// Create static token provider if enabled
	if enabledProviders["static"] {
		staticProvider := authn.NewStaticProvider()
		
		// TODO: Load tokens from configuration
		// For now, create a default admin token (dev only)
		// In production, tokens should be loaded from secure storage
		
		providers = append(providers, staticProvider)
		logger.Info("Static authentication provider enabled")
	}

	// Create mTLS provider if enabled
	if enabledProviders["mtls"] {
		mtlsProvider := authn.NewMTLSProvider()
		providers = append(providers, mtlsProvider)
		logger.Info("mTLS authentication provider enabled")
	}

	// Create SPIFFE provider if enabled
	if enabledProviders["spiffe"] {
		spiffeConfig := &authn.SPIFFEConfig{
			TrustDomain:    cfg.Security.Auth.SPIFFE.TrustDomain,
			BundlePaths:    cfg.Security.Auth.SPIFFE.BundlePaths,
			WorkloadSocket: cfg.Security.Auth.SPIFFE.WorkloadSocket,
		}
		
		spiffeProvider, err := authn.NewSPIFFEProvider(spiffeConfig)
		if err != nil {
			logger.Fatal("Failed to initialize SPIFFE provider", zap.Error(err))
		}
		
		providers = append(providers, spiffeProvider)
		logger.Info("SPIFFE authentication provider enabled",
			zap.String("trust_domain", cfg.Security.Auth.SPIFFE.TrustDomain))
	}

	// Create auth manager with configured providers
	return authn.NewManager(providers...)
}

// setupMiddleware sets up HTTP middleware
func setupMiddleware(
	httpServer *server.Server,
	authManager *authn.Manager,
	authzEngine *authz.Engine,
	auditLogger *audit.Logger,
	logger *zap.Logger,
	cfg *config.Config,
) {
	router := httpServer.Router()

	// Audit middleware (should be first to log all requests)
	router.Use(audit.Middleware(auditLogger, logger))

	// Authentication middleware
	if cfg.Server.RequireClientCert {
		// mTLS is required, use optional auth for tokens
		router.Use(authn.OptionalAuth(authManager, logger))
	} else {
		// Use required auth
		router.Use(authn.RequireAuth(authManager, logger))
	}

	// Authorization middleware
	router.Use(authz.Middleware(authzEngine, logger))
}
