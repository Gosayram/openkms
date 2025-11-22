# SPIFFE Authentication Examples

This directory contains examples for configuring OpenKMS with SPIFFE authentication.

## Overview

SPIFFE (Secure Production Identity Framework for Everyone) provides a standardized way to issue and verify service identities using X.509 SVIDs.

## Examples

### 1. Basic SPIFFE Configuration

```yaml
# config.yaml
security:
  auth:
    providers:
      - static
      - mtls
      - spiffe
    spiffe:
      trust_domain: "example.org"
      workload_socket: "/tmp/spire-agent/public/api.sock"
```

### 2. SPIFFE with Trust Bundle Files

```yaml
# config-with-bundles.yaml
security:
  auth:
    providers:
      - static
      - mtls
      - spiffe
    spiffe:
      trust_domain: "example.org"
      bundle_paths:
        - "/etc/spiffe/trust-bundle.pem"
        - "/etc/spiffe/backup-bundle.pem"
```

### 3. Environment Variables

```bash
# Enable SPIFFE authentication
export OPENKMS_AUTH_PROVIDERS=static,mtls,spiffe
export OPENKMS_SPIFFE_TRUST_DOMAIN=example.org
export OPENKMS_SPIFFE_WORKLOAD_SOCKET=/tmp/spire-agent/public/api.sock
```

### 4. Docker Compose with SPIRE

```yaml
# docker-compose.yml
version: '3.8'

services:
  spire-server:
    image: ghcr.io/spiffe/spire-server:latest
    command: ["-config", "/conf/server/server.conf"]
    volumes:
      - ./conf/server:/conf/server
      - ./data:/data
    ports:
      - "8081:8081"

  spire-agent:
    image: ghcr.io/spiffe/spire-agent:latest
    command: ["-config", "/conf/agent/agent.conf"]
    volumes:
      - ./conf/agent:/conf/agent
      - /tmp/spire-agent/public:/tmp/spire-agent/public
    depends_on:
      - spire-server

  openkms:
    image: openkms:latest
    environment:
      - OPENKMS_AUTH_PROVIDERS=static,mtls,spiffe
      - OPENKMS_SPIFFE_TRUST_DOMAIN=example.org
      - OPENKMS_SPIFFE_WORKLOAD_SOCKET=/tmp/spire-agent/public/api.sock
      - OPENKMS_TLS_ENABLED=true
      - OPENKMS_TLS_REQUIRE_CLIENT_CERT=true
    volumes:
      - spire-agent-socket:/tmp/spire-agent/public
    ports:
      - "8443:8443"
    depends_on:
      - spire-agent

volumes:
  spire-agent-socket:
    driver: local
```

### 5. Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openkms-config
data:
  OPENKMS_AUTH_PROVIDERS: "static,mtls,spiffe"
  OPENKMS_SPIFFE_TRUST_DOMAIN: "example.org"
  OPENKMS_SPIFFE_WORKLOAD_SOCKET: "/tmp/spire-agent/public/api.sock"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openkms
spec:
  replicas: 3
  selector:
    matchLabels:
      app: openkms
  template:
    metadata:
      labels:
        app: openkms
    spec:
      containers:
      - name: openkms
        image: openkms:latest
        envFrom:
        - configMapRef:
            name: openkms-config
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /tmp/spire-agent/public
        ports:
        - containerPort: 8443
          name: https
      volumes:
      - name: spire-agent-socket
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: openkms
spec:
  selector:
    app: openkms
  ports:
  - port: 8443
    targetPort: 8443
    name: https
    protocol: TCP
```

## SPIFFE Configuration Files

### SPIRE Server Configuration

```hcl
# server.conf
server {
    trust_domain = "example.org"
    bind_address = "0.0.0.0"
    bind_port = 8081
    
    data_dir = "/data"
    
    log_level = "INFO"
    
    default_svid_ttl = "1h"
    default_bundle_ttl = "1h"
}

plugins {
    DataStore "sql" {
        plugin_data_source = "sqlite3:///data/spire_server.sqlite"
        database_path = "/data/spire_server.sqlite"
    }
    
    NodeAttestor "join_token" {
        trust_domain = "example.org"
        join_token = "your-join-token-here"
    }
    
    Notifier "notifier" {
        skip_upstream_spiffe_bundle = true
    }
}
```

### SPIRE Agent Configuration

```hcl
# agent.conf
agent {
    data_dir = "/tmp/spire-agent"
    log_level = "INFO"
    
    server_address = "spire-server:8081"
    trust_domain = "example.org"
    
    join_token = "your-join-token-here"
}

plugins {
    NodeAttestor "k8s_psat" {
        cluster_manager_endpoint = "kubernetes.default.svc"
        service_account_allow_list = ["openkms"]
    }
    
    KeyManager "memory" {
        cache_dir = "/tmp/spire-agent"
    }
    
    WorkloadAttestor "k8s" {
        workload_api_socket_path = "/tmp/spire-agent/public/api.sock"
    }
}
```

## Testing SPIFFE Integration

### 1. Generate Test Certificate

```bash
# Create a test SPIFFE SVID
openssl req -x509 -newkey rsa:2048 -nodes -keyout test-key.pem \
    -out test-cert.pem -days 365 -subj "/CN=spiffe://example.org/test-service" \
    -addext "subjectAltName=URI:spiffe://example.org/test-service"
```

### 2. Test with curl

```bash
# Test authentication with SPIFFE certificate
curl -k --cert test-cert.pem --key test-key.pem \
    https://localhost:8443/v1/key
```

### 3. Verify Certificate

```bash
# Check SPIFFE ID in certificate
openssl x509 -in test-cert.pem -text -noout | grep "URI:"
```

## Security Considerations

### Trust Domain Isolation

- Services from different trust domains cannot authenticate to each other
- Configure trust domain carefully to match your SPIFFE deployment
- Use separate trust domains for different environments (prod, staging, dev)

### Certificate Validation

- SPIFFE IDs must belong to the configured trust domain
- Certificate validity period is automatically checked
- Certificate chain verification is performed when trust bundles are available

### Workload API Security

- Ensure workload API socket is properly secured
- Use file permissions to restrict access to the socket
- Consider using Unix domain sockets for local communication

## Troubleshooting

### Common Issues

1. **"failed to initialize SPIFFE bundle"**
   - Check that trust domain is correctly configured
   - Verify bundle files exist and are readable
   - Ensure workload API is accessible

2. **"SVID trust domain does not match expected"**
   - Verify client certificate contains correct SPIFFE ID
   - Check trust domain configuration matches SPIFFE deployment

3. **"failed to extract SPIFFE ID from certificate"**
   - Ensure certificate contains SPIFFE ID in URI SAN
   - Verify certificate format is correct

### Debug Commands

```bash
# Check if workload API is available
curl --unix-socket /tmp/spire-agent/public/api.sock http://localhost/

# Verify certificate SPIFFE ID
openssl x509 -in client.crt -text -noout | grep -A1 "URI:"

# Check OpenKMS logs for SPIFFE authentication
docker logs openkms | grep "spiffe"
```

## Migration Guide

### From mTLS to SPIFFE

1. Configure SPIFFE trust domain
2. Enable SPIFFE provider alongside mTLS
3. Gradually migrate clients to use SPIFFE SVIDs
4. Once all clients use SPIFFE, disable mTLS provider

### Configuration Migration

```bash
# Before (mTLS only)
OPENKMS_AUTH_PROVIDERS=static,mtls

# During migration (both enabled)
OPENKMS_AUTH_PROVIDERS=static,mtls,spiffe
OPENKMS_SPIFFE_TRUST_DOMAIN=example.org

# After migration (SPIFFE only)
OPENKMS_AUTH_PROVIDERS=static,spiffe
OPENKMS_SPIFFE_TRUST_DOMAIN=example.org
```

## Best Practices

1. **Use Workload API**: Prefer workload API over manual bundle files for dynamic trust management
2. **Configure Trust Domain**: Use a consistent trust domain across your organization
3. **Monitor Certificate Expiration**: Implement monitoring for SVID expiration
4. **Secure Socket Access**: Restrict access to workload API socket
5. **Test Authentication**: Verify SPIFFE authentication works in your environment
6. **Backup Trust Bundles**: Keep backup copies of trust bundles for disaster recovery
7. **Document Configuration**: Maintain clear documentation of your SPIFFE setup

## Integration with Service Mesh

When using with service mesh (like Istio), ensure that service mesh allows SPIFFE SVIDs to pass through:

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: openkms-spiffe
spec:
  selector:
    matchLabels:
      app: openkms
  mtls:
    mode: STRICT
  portLevelMtls:
    "8443":
      mode: STRICT
```

## Monitoring and Observability

### Metrics

OpenKMS provides metrics for SPIFFE authentication:

- `authn_spiffe_success_total`: Number of successful SPIFFE authentications
- `authn_spiffe_failure_total`: Number of failed SPIFFE authentications
- `authn_spiffe_duration_seconds`: Duration of SPIFFE authentication operations

### Logging

SPIFFE authentication events are logged with the following metadata:

- SPIFFE ID
- Trust domain
- Certificate serial number
- Certificate validity period
- Authentication result

## Additional Resources

- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
- [SPIRE Documentation](https://github.com/spiffe/spire/blob/main/doc/user_guide.md)
- [OpenKMS Documentation](https://github.com/Gosayram/openkms)