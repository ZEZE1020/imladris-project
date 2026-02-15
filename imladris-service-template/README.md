# Imladris Service Template

Production-ready Go microservice template for the Imladris platform.

## Overview

Provides a "golden path" for developing zero-trust banking services with:
- HTTP server with health check endpoints
- Prometheus metrics export
- Kubernetes manifests and CI/CD pipeline
- Distroless container with non-root execution
- VPC Lattice service mesh integration

## Service Structure

```go
// main.go - HTTP server with:
├── Health & Readiness Endpoints (/health, /ready)
├── Business Logic (/api/v1/accounts)
├── Prometheus Metrics (/metrics on port 9090)
├── Service Discovery (/.well-known/service)
└── Graceful Shutdown (SIGTERM handling)
```

## Getting Started

### Clone and Customize

```bash
# Clone the template
git clone https://github.com/ZEZE1020/imladris-service-template.git my-service
cd my-service

# Update Go module name
go mod edit -module github.com/ZEZE1020/my-service

# Update service configuration
export SERVICE_NAME="my-service"
export NAMESPACE="my-namespace"

# Find and replace template values
find . -name "*.yaml" -o -name "*.go" -o -name "*.yml" | \
  xargs sed -i "s/banking-core-service/$SERVICE_NAME/g"
```

### Develop Locally

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Run locally
export PORT=8080
export METRICS_PORT=9090
export LOG_LEVEL=debug
go run main.go
```

### Test Endpoints

```bash
# Health check
curl http://localhost:8080/health

# Business endpoint
curl http://localhost:8080/api/v1/accounts?account_id=test-123

# Metrics
curl http://localhost:9090/metrics

# Service discovery
curl http://localhost:8080/.well-known/service
```

### Container Testing

```bash
# Build container
docker build -t my-service:latest .

# Run container
docker run -p 8080:8080 -p 9090:9090 \
  -e ENVIRONMENT=dev \
  -e SERVICE_NAME=my-service \
  my-service:latest

# Security scan
docker run --rm -v $(pwd):/app \
  aquasec/trivy image my-service:latest
```

## CI/CD Pipeline

The GitHub Actions workflow includes:

### Security Gates
- GoSec static code analysis
- Trivy container vulnerability scanning
- Conftest/OPA manifest validation
- SBOM generation
- Compliance checks

### Build Process
- Unit tests with coverage
- Statically linked Go binary
- Multi-stage Docker build with distroless base
- Secure push to Amazon ECR
- GitOps manifest update

### Deployment Flow
- GitOps commit to update manifests
- ArgoCD automatic sync to EKS Fargate
- Kubernetes health checks
- VPC Lattice service mesh registration
- Prometheus monitoring setup

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP server port | `8080` |
| `METRICS_PORT` | Metrics server port | `9090` |
| `LOG_LEVEL` | Logging level | `info` |
| `LOG_FORMAT` | Log format (json/text) | `json` |
| `SERVICE_NAME` | Service identifier | `banking-core-service` |
| `ENVIRONMENT` | Deployment environment | `dev` |
| `AWS_REGION` | AWS region | `us-east-1` |

### Kubernetes Resources

```yaml
resources:
  limits:
    cpu: "500m"
    memory: "512Mi"
    ephemeral-storage: "1Gi"
  requests:
    cpu: "100m"
    memory: "128Mi"
    ephemeral-storage: "100Mi"
```

## Security Features

### Container Security
- Non-root execution (user ID 65534)
- Distroless base image (no shell or package manager)
- Read-only filesystem
- Security context with comprehensive pod controls
- CPU, memory, and storage limits

### Observability
- Structured JSON logging
- Prometheus metrics for HTTP requests and business operations
- Kubernetes liveness, readiness, and startup probes
- OpenTelemetry integration ready

## VPC Lattice Integration

Services automatically integrate with VPC Lattice through:
- Service annotations for VPC Lattice load balancer
- Kubernetes probes become Lattice health checks
- AWS IAM-based service-to-service authentication
- DNS-based service discovery

Example service call with IAM authentication:

```go
// Call another service via VPC Lattice
client := &http.Client{}
req, _ := http.NewRequest("GET", "https://payments.imladris.prod.local/api/v1/status", nil)

// AWS Sigv4 signing for VPC Lattice
signer := v4.NewSigner()
signer.Sign(req, nil, "vpc-lattice", "us-east-1", time.Now())

resp, err := client.Do(req)
```

## Monitoring

### Metrics

- `http_requests_total`: HTTP requests by method, endpoint, status
- `http_request_duration_seconds`: Request latency histogram
- `business_operations_total`: Business operation counters

### Alerts

```yaml
groups:
- name: my-service
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status_code=~"5.."}[5m]) > 0.1
    for: 5m
    annotations:
      summary: "High error rate detected"

  - alert: HighLatency
    expr: histogram_quantile(0.95, http_request_duration_seconds_bucket) > 0.5
    for: 5m
    annotations:
      summary: "High latency detected"
```

## Compliance

### Banking Regulations
- PCI DSS: No sensitive data logging, encrypted communications
- SOX: Audit trails, change management via GitOps
- GDPR: Data protection, right to erasure support
- FFIEC: Risk management, incident response procedures

### Zero Trust Controls
- Identity verification: AWS IAM service-to-service authentication
- Least privilege: Minimal container permissions
- Encryption: TLS for all communications via VPC Lattice
- Monitoring: Comprehensive logging and metrics
- Policy enforcement: OPA/Conftest validation

## Troubleshooting

### Common Issues

```bash
# Container won't start
kubectl logs -f deployment/my-service -c my-service

# Health check failures
kubectl describe pod my-service-xxx

# VPC Lattice connectivity
aws vpc-lattice get-service --service-identifier my-service-id

# ArgoCD sync issues
argocd app get my-service --show-params
```

### Emergency Procedures

```bash
# Scale down service
kubectl scale deployment my-service --replicas=0

# Emergency rollback
argocd app rollback my-service $(argocd app history my-service -o id | tail -2 | head -1)

# Break glass deployment (bypass GitOps)
kubectl set image deployment/my-service my-service=image:previous-tag
```

## Integration

Works with:
- [imladris-platform](../imladris-platform): EKS cluster and VPC Lattice
- [imladris-governance](../imladris-governance): Policy validation
- [imladris-gitops](../imladris-gitops): Deployment manifests and ArgoCD