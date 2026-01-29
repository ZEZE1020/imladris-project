# Imladris: Zero Trust Banking Platform

A reference Internal Developer Platform (IDP) for investment banks implementing zero trust architecture, policy-as-code governance, and automated compliance.

## Overview

Imladris provides a secure, compliant AWS environment that:

- Eliminates VPNs with zero-trust networking via VPC Lattice
- Enforces immutable infrastructure using EKS Fargate exclusively
- Automates security remediation using AWS Config, EventBridge, and SSM
- Validates all changes through policy-as-code before deployment
- **NEW**: Secures the software supply chain with Harbor container registry and vulnerability scanning

## What's New: Supply Chain Security

🚀 **Latest Enhancement**: We've added a **Harbor-based Secure Pull-Through Cache** that creates an impenetrable defense against supply chain attacks while maintaining developer velocity.

**Key Benefits:**
- ✅ **Zero Internet Builds**: Build processes never directly access public registries
- ✅ **Critical CVE Blocking**: Automatic rejection of vulnerable base images
- ✅ **Banking Compliance**: Complete audit trail for regulatory requirements
- ✅ **Offline Resilience**: Local caching eliminates external dependencies

## Platform Architecture

The platform consists of four integrated components with **enhanced supply chain security**:

```
Developer Code → Policy Validation → Infrastructure → Kubernetes Applications
     GitHub          OPA/Rego         Terraform      ArgoCD Deployment
                   (Governance)       (Platform)       (GitOps)
```

### Enhanced Supply Chain Security (NEW)
We've added a **Hybrid Registry Model** that creates a secure firewall for all container dependencies:

```
Docker Hub → Harbor (Scan & Cache) → CI/CD Build → ECR → EKS Fargate
             Supply Chain Security   Application    Deployment
                  Firewall            Images        Registry
```

**How it works:**
- **Harbor's Role**: Cache, scan, and serve public base images (from Docker Hub/Quay) to the build environment. This ensures we never pull directly from the internet during builds.
- **ECR's Role**: Store the final, compiled application images that are deployed to EKS Fargate.
- **Why Both?**: Harbor sanitizes the inputs (Base Images); ECR secures the outputs (App Images).

### Core Architecture Layers
- **Infrastructure**: Terraform modules for VPC, EKS, VPC Lattice, and self-healing controls
- **Supply Chain Security**: NEW - Harbor proxy cache with vulnerability scanning for all upstream dependencies
- **Governance**: OPA policies enforcing zero-public-access, VPC Lattice, and Fargate-only compute
- **GitOps**: ArgoCD managing application state across Kubernetes clusters
- **Services**: Go template for rapid development of compliant microservices

## Repository Structure

### [imladris-platform/](./imladris-platform/)
Infrastructure as Code using Terraform. Provides:
- Private VPC (10.0.0.0/16) with no internet gateway
- VPC Lattice for service-to-service communication
- EKS Fargate cluster for containerized workloads
- **NEW**: Harbor Container Registry with secure pull-through cache for supply chain protection
- AWS Config, EventBridge, and SSM for automated remediation
- IAM Identity Center for centralized access control

### [imladris-governance/](./imladris-governance/)
Policy-as-Code using OPA and Conftest. Enforces:
- No public ingress (blocks 0.0.0.0/0 access on all ports)
- VPC Lattice mandatory for service communication
- Fargate-only compute (prohibits EC2 instances)
- HTTPS encryption for all listeners

### [imladris-gitops/](./imladris-gitops/)
GitOps configuration using ArgoCD. Manages:
- App-of-apps pattern for centralized deployment
- Tenant namespaces (banking-core, platform, monitoring)
- Network policies with default-deny rules
- VPC Lattice service mesh integration

### [imladris-service-template/](./imladris-service-template/)
Production-ready service template in Go. Includes:
- HTTP server with health check endpoints
- Prometheus metrics export
- Kubernetes manifests and CI/CD pipeline
- Distroless container with non-root execution
- VPC Lattice integration ready

## Quick Start

See [SETUP.md](./SETUP.md) for complete setup instructions.
See [DEPLOYMENT.md](./DEPLOYMENT.md) for deployment procedures.

### Prerequisites

- Terraform >= 1.0
- AWS CLI >= 2.31
- kubectl >= 1.28
- Conftest >= 0.46

### Basic Deployment

```bash
# Configure and deploy infrastructure
cd imladris-platform
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply

# Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name imladris-cluster

# Deploy GitOps
cd ../imladris-gitops
kubectl apply -f bootstrap/root.yaml
```

## Security Model

### Zero Trust Principles
- No VPN access; all access through IAM Identity Center
- No public endpoints; VPC Lattice handles all service communication
- No SSH access; containers are immutable
- Encrypted in transit; TLS enforced everywhere
- Least privilege; minimal IAM permissions

### Supply Chain Validation (NEW SECURITY LAYER)
- **Dependency Firewall**: All base images are sourced exclusively from the internal Harbor proxy, ensuring 100% vulnerability screening before the build process begins
- **Critical Vulnerability Blocking**: Images with Critical CVEs are automatically blocked from being served to build environments
- **Dependency Confusion Prevention**: Prevents 'Dependency Confusion' attacks and outages by enforcing a single, scanned entry point for all open-source libraries
- **Offline Resilience**: Critical build dependencies are cached locally, allowing development to continue even during upstream outages
- **Supply Chain Transparency**: Complete audit trail of all base images used in production deployments

### Automated Compliance
- AWS Config monitors all resource changes
- EventBridge triggers remediation on policy violations
- SSM Automation reverts non-compliant changes
- Continuous validation through OPA policies
- **NEW**: Harbor Trivy scanner validates all cached images for known vulnerabilities

## Architecture Decisions

### Why VPC Lattice?
AWS-native service mesh with IAM integration, no additional infrastructure required.

### Why Fargate?
Immutable compute eliminates persistent state vulnerability, managed patching by AWS.

### Why GitOps?
Git audit trail, drift detection, simple rollback, no external access to cluster.

### Why Harbor Secure Registry? (NEW)
Investment banking requires complete control over the software supply chain. Harbor provides:
- **Zero Internet Dependencies**: Build processes never touch public registries directly
- **Banking Compliance**: Complete audit trail of all base images for regulatory reporting
- **Vulnerability Prevention**: Critical CVE blocking prevents compromised images from entering production
- **Operational Resilience**: Local caching eliminates dependency on external service availability