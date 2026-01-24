# Imladris GitOps

ArgoCD-based GitOps platform for managing Kubernetes workload state.

## Overview

Manages desired state of all Kubernetes workloads using ArgoCD with:
- App-of-apps pattern for centralized application management
- Network policies enforcing default-deny with explicit allow rules
- VPC Lattice integration for zero-trust service communication
- Policy validation through Conftest/OPA before deployment

## Architecture

ArgoCD monitors Git repository and keeps cluster state synchronized:

1. Developer commits manifest changes to Git
2. GitOps webhook notifies ArgoCD
3. ArgoCD detects drift from desired state
4. Policies are validated (Conftest/OPA)
5. Changes are automatically deployed to cluster
6. Continuous monitoring detects and remediates drift

## Structure

```
imladris-gitops/
├── bootstrap/
│   └── root.yaml              # Root App-of-Apps application
├── tenants/
│   └── banking-core/          # Core banking services namespace
│       ├── namespace.yaml     # Namespace with network policies
│       ├── deployment.yaml    # Service deployment
│       ├── service.yaml       # Kubernetes service
│       └── vpc-lattice-service.yaml  # VPC Lattice integration
└── infrastructure/
    └── argocd/                # ArgoCD configuration
        ├── argocd-server.yaml
        └── argocd-repo-server.yaml
```

## Components

### Bootstrap Layer
- Root Application: App-of-apps managing all applications
- App Projects: RBAC boundaries and security isolation
- Repository Configuration: Git credentials and access

### Tenant Layer
- banking-core: Core banking services namespace
- platform: Infrastructure and tooling namespace
- monitoring: Observability and alerting namespace

### Security Layer
- Network Policies: Default-deny with explicit allow rules
- VPC Lattice Integration: Service mesh for zero-trust communication
- RBAC: Fine-grained access control via IAM Identity Center

## Tenant Onboarding

### 1. Create Namespace Structure

```bash
mkdir -p tenants/{tenant-name}
cd tenants/{tenant-name}
```

### 2. Define Base Resources

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: {tenant-name}
  labels:
    name: {tenant-name}
    tier: application
    compliance: pci-dss
```

### 3. Application Manifests

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {service-name}
  namespace: {tenant-name}
spec:
  # Your deployment configuration
```

### 4. VPC Lattice Integration

```yaml
# vpc-lattice-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: {service-name}-lattice
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "external"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internal"
```

## Security Policies

### Network Policies
- Default deny-all policy for all namespaces
- Explicit allow rules for required communication
- VPC Lattice traffic automatically allowed
- ArgoCD management traffic permitted

### Resource Policies
- All pods must run as non-root
- Memory and CPU limits required
- Proper labeling for service discovery
- Approved container registries only

### RBAC Integration
- IAM Identity Center SSO integration
- Project-based access controls
- Platform admin for full cluster access
- Read-only access for auditors

## Usage

### Deploy New Application

1. Create manifests in `tenants/{namespace}/`
2. Commit and push to Git repository
3. ArgoCD automatically detects and deploys
4. Monitor status in ArgoCD UI

### Update Existing Application

1. Modify manifests in Git repository
2. Push changes to trigger sync
3. ArgoCD validates with policies
4. Automatic rollout if validation passes

### Rollback Application

Via ArgoCD CLI:
```bash
argocd app rollback {app-name} {revision-id}
```

Via ArgoCD UI:
- Navigate to application → History
- Select revision → Rollback

### Emergency Procedures

Suspend automatic sync (break glass):
```bash
argocd app patch {app-name} --patch '{"spec":{"syncPolicy":null}}'
```

Manual sync with policy override (admin only):
```bash
argocd app sync {app-name} --force --replace
```

Re-enable automatic sync:
```bash
argocd app patch {app-name} --patch '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}'
```

## Monitoring

### Application Health
- ArgoCD deployment status
- Kubernetes resource health
- Policy compliance validation
- Configuration drift detection

### Service Mesh Metrics
- VPC Lattice communication metrics
- Network policy traffic flow
- Security event alerting
- Performance latency tracking

## Integration

Works with:
- [imladris-platform](../imladris-platform): EKS cluster and VPC Lattice
- [imladris-governance](../imladris-governance): Policy validation
- [imladris-service-template](../imladris-service-template): Application development
- AWS IAM Identity Center: Authentication and authorization