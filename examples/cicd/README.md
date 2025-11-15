# CI/CD Integration Examples

This directory contains examples of integrating OpenKMS with various CI/CD systems for artifact signing.

## Overview

OpenKMS supports Cosign-compatible artifact signing, which allows integration into CI/CD pipelines for:
- Signing Docker images
- Signing binary files
- Signing archives and other artifacts
- Verifying signatures before deployment

## Examples

### GitHub Actions
- [Docker image signing](./github-actions/docker-sign.yml)
- [Binary file signing](./github-actions/binary-sign.yml)
- [Full example with verification](./github-actions/full-pipeline.yml)

### GitLab CI
- [Docker image signing](./gitlab-ci/docker-sign.gitlab-ci.yml)
- [Binary file signing](./gitlab-ci/binary-sign.gitlab-ci.yml)

### Jenkins
- [Jenkinsfile for artifact signing](./jenkins/Jenkinsfile)

### Utilities
- [Script for signing artifacts](./scripts/sign-artifact.sh)
- [Go utility for signing](./scripts/sign-artifact.go)

## Requirements

1. Running OpenKMS server instance
2. Signing key (Ed25519) created in OpenKMS
3. Authentication token or mTLS certificates
4. OpenKMS CLI or SDK for signing

## Setup

### 1. Create signing key

```bash
# Create Ed25519 key for signing
./bin/openkms-cli create-key \
  --id signing-key \
  --type signing-key \
  --algorithm ed25519 \
  --server-url https://openkms.example.com \
  --token YOUR_TOKEN
```

### 2. Get public key

```bash
# Export public key for verification
./bin/openkms-cli get-key signing-key \
  --server-url https://openkms.example.com \
  --token YOUR_TOKEN \
  --public-key > cosign.pub
```

### 3. Configure secrets in CI/CD

#### GitHub Actions
```yaml
secrets:
  OPENKMS_URL: https://openkms.example.com
  OPENKMS_TOKEN: your-token-here
  OPENKMS_KEY_ID: signing-key
```

#### GitLab CI
```yaml
variables:
  OPENKMS_URL: https://openkms.example.com
  OPENKMS_KEY_ID: signing-key
```

In GitLab CI/CD Settings → Variables add:
- `OPENKMS_TOKEN` (masked)

#### Jenkins
In Jenkins Credentials add:
- `OPENKMS_URL`
- `OPENKMS_TOKEN`
- `OPENKMS_KEY_ID`

## Usage

### Sign Docker image

```bash
# Using CLI
./bin/openkms-cli sign \
  --key-id signing-key \
  --file artifact.tar.gz \
  --server-url $OPENKMS_URL \
  --token $OPENKMS_TOKEN

# Using script
./examples/cicd/scripts/sign-artifact.sh \
  --key-id signing-key \
  --file artifact.tar.gz \
  --url $OPENKMS_URL \
  --token $OPENKMS_TOKEN
```

### Verify signature

```bash
# Using Cosign CLI (compatible with OpenKMS signatures)
cosign verify-blob \
  --key cosign.pub \
  --signature artifact.tar.gz.sig \
  artifact.tar.gz
```

## Security

- Never store tokens in plain text in the repository
- Use CI/CD system secrets to store tokens
- Use mTLS for additional security
- Regularly rotate signing keys
- Store public keys in a secure location for verification

## Additional Resources

- [OpenKMS README](../../README.md)
- [Cosign documentation](https://docs.sigstore.dev/cosign/overview/)
