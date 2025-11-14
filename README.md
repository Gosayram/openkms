# OpenKMS

OpenKMS is a skeleton implementation of a Key Management Service (KMS) written in Go. It provides a foundation for building production-ready key management systems with essential security features and extensible architecture.

## Overview

OpenKMS is designed as a modular, secure, and scalable key management service that handles cryptographic key lifecycle, encryption/decryption operations, digital signatures, and HMAC computation. The project serves as a starting point for organizations that need a custom KMS solution tailored to their specific requirements.

## Features

### Core Functionality

- **Key Management**: Create, retrieve, list, and delete cryptographic keys
- **Cryptographic Operations**: Encryption, decryption, digital signing, signature verification, and HMAC computation
- **Key Lifecycle**: Full key lifecycle management with versioning and rotation support
- **Key Rewrap**: Re-encrypt ciphertext with new key versions without exposing plaintext

### Security

- **Multiple Storage Backends**: Support for BoltDB, PostgreSQL, and file-based storage
- **Envelope Encryption**: All keys are encrypted at rest using envelope encryption
- **Multiple Authentication Methods**: Static tokens, mTLS, and OIDC/JWT authentication
- **Authorization**: Role-based access control (RBAC) using Casbin
- **Audit Logging**: Comprehensive audit logging with cryptographic signing
- **Audit Retention**: Configurable retention policies for audit logs

### Operations

- **CLI Tool**: Command-line interface for key management and operations
- **REST API**: HTTP/HTTPS API for programmatic access
- **Metrics**: Prometheus metrics for monitoring and observability
- **Health Checks**: Health check endpoints for service monitoring

## Project Status

This is a skeleton implementation. The project provides a solid foundation with core functionality implemented, but it is not production-ready and requires additional work for specific use cases. Key areas that may need enhancement include:

- Production-grade storage backends
- Advanced key rotation policies
- High availability and clustering
- Backup and disaster recovery
- Performance optimization
- Additional security hardening

## Getting Started

### Prerequisites

- Go 1.25 or later
- Make (for build automation)

### Building

```bash
make build
```

This will build both the server (`openkms-server`) and CLI (`openkms-cli`) binaries.

### Running the Server

```bash
./bin/openkms-server
```

The server will start on `localhost:8080` by default. Configuration can be provided via environment variables (see `internal/config/config.go` for available options).

### Using the CLI

```bash
./bin/openkms-cli --help
```

## Project Structure

```
openkms/
  cmd/
    openkms-server/    # Server application
    openkms-cli/       # CLI tool
  internal/
    audit/             # Audit logging and signing
    authn/             # Authentication
    authz/             # Authorization (Casbin)
    config/            # Configuration management
    cryptoengine/      # Cryptographic operations
    keystore/          # Key storage and management
    logging/           # Structured logging
    metrics/           # Prometheus metrics
    policies/          # Security policies
    server/            # HTTP server and handlers
    storage/           # Storage backends
  pkg/
    sdk/               # Client SDK
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](#LICENSE) file for details.

## Contributing

This is a skeleton project. Contributions, improvements, and feedback are welcome. Please ensure all code follows the project's coding standards and includes appropriate tests.

## Repository

https://github.com/Gosayram/openkms

