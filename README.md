# Imladris: Zero Trust Banking Platform

[![Terraform](https://img.shields.io/badge/Terraform-1.0+-purple.svg)](https://www.terraform.io/)
[![AWS](https://img.shields.io/badge/AWS-EKS%20%7C%20VPC%20Lattice-orange.svg)](https://aws.amazon.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OPA](https://img.shields.io/badge/Policy-OPA%2FRego-green.svg)](https://www.openpolicyagent.org/)

A production-grade **Internal Developer Platform (IDP)** reference architecture for investment banks, implementing zero-trust networking, policy-as-code governance, and automated compliance on AWS.

---

## 🎯 Project Overview

**Imladris** (named after the hidden Elven refuge in Tolkien's universe) provides a secure, compliant AWS environment designed for financial services organizations requiring:

- **Zero Trust Architecture** — No VPNs, no public endpoints, IAM-based access everywhere
- **Immutable Infrastructure** — EKS Fargate exclusively, no persistent EC2 instances
- **Policy-as-Code** — All changes validated through OPA/Rego before deployment
- **Automated Remediation** — Self-healing infrastructure via AWS Config + EventBridge + SSM
- **GitOps Workflows** — Declarative state management with ArgoCD

### Target Audience

| Role | Value Proposition |
|------|------------------|
| **Platform Engineers** | Production-ready IDP with modular Terraform |
| **Security Engineers** | Zero-trust implementation with policy enforcement |
| **DevOps Engineers** | GitOps patterns with automated compliance |
| **Solutions Architects** | Reference architecture for regulated industries |

---

## 🏗️ Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IMLADRIS PLATFORM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Developer → GitHub → Policy Gate → Terraform → AWS → Kubernetes → Service │
│                           (OPA)       (IaC)     (Infra)  (ArgoCD)   (App)   │
│                                                                              │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────────┤
│  GOVERNANCE  │  NETWORKING  │   COMPUTE    │   GITOPS     │    SERVICES     │
├──────────────┼──────────────┼──────────────┼──────────────┼─────────────────┤
│ • OPA/Rego   │ • VPC Lattice│ • EKS Fargate│ • ArgoCD     │ • Go Template   │
│ • Conftest   │ • Private VPC│ • No EC2     │ • App-of-Apps│ • Distroless    │
│ • AWS Config │ • No IGW     │ • KMS Encrypt│ • Auto-Sync  │ • Prometheus    │
│ • EventBridge│ • VPC Endpts │ • IAM IRSA   │ • Self-Heal  │ • Health Checks │
└──────────────┴──────────────┴──────────────┴──────────────┴─────────────────┘
```

### Zero Trust Network Design

```
┌─────────────────────────────────────────────────────────────────┐
│                     AWS ACCOUNT                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  VPC (10.0.0.0/16)                         │  │
│  │                  ❌ No Internet Gateway                    │  │
│  │                  ❌ No NAT Gateway                         │  │
│  │                  ❌ No Public Subnets                      │  │
│  │                                                            │  │
│  │   ┌─────────────────────────────────────────────────────┐ │  │
│  │   │              PRIVATE SUBNETS ONLY                    │ │  │
│  │   │  ┌─────────┐  ┌─────────┐  ┌─────────┐             │ │  │
│  │   │  │ EKS     │  │ EKS     │  │ EKS     │             │ │  │
│  │   │  │ Fargate │  │ Fargate │  │ Fargate │             │ │  │
│  │   │  │ (AZ-1a) │  │ (AZ-1b) │  │ (AZ-1c) │             │ │  │
│  │   │  └────┬────┘  └────┬────┘  └────┬────┘             │ │  │
│  │   │       │            │            │                   │ │  │
│  │   │       └────────────┼────────────┘                   │ │  │
│  │   │                    │                                │ │  │
│  │   │            ┌───────▼───────┐                        │ │  │
│  │   │            │  VPC LATTICE  │ ← Service Mesh         │ │  │
│  │   │            │  (IAM Auth)   │                        │ │  │
│  │   │            └───────────────┘                        │ │  │
│  │   └─────────────────────────────────────────────────────┘ │  │
│  │                                                            │  │
│  │   ┌─────────────────────────────────────────────────────┐ │  │
│  │   │              VPC ENDPOINTS                           │ │  │
│  │   │  • S3 (Gateway)    • ECR API      • ECR Docker      │ │  │
│  │   │  • EKS             • CloudWatch   • SSM             │ │  │
│  │   └─────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
imladris-project/
├── README.md                    # This file
├── docs/                        # Documentation
│   ├── DEPLOYMENT.md           # Deployment procedures
│   ├── architecture/           # Architecture decisions
│   │   └── RBAC-DESIGN.md     # RBAC design document
│   └── setup/                  # Setup guides
│       ├── SETUP.md           # Complete setup instructions
│       └── AWS-SETUP-GUIDE.md # AWS-specific setup
│
├── imladris-platform/          # 🏗️ Infrastructure as Code
│   ├── main.tf                # Root module composition
│   ├── variables.tf           # Input variables
│   ├── outputs.tf             # Output values
│   └── modules/
│       ├── networking/        # VPC, Lattice, Endpoints
│       ├── compute/           # EKS Fargate, IAM
│       ├── governance/        # Config, EventBridge, SSM
│       └── secure-registry/   # Harbor (optional)
│
├── imladris-governance/        # 📜 Policy as Code
│   ├── conftest.yaml          # Conftest configuration
│   └── policies/
│       └── terraform/         # Terraform plan policies
│           ├── deny-public-ingress.rego
│           ├── enforce-fargate.rego
│           └── require-vpc-lattice.rego
│
├── imladris-gitops/            # 🔄 GitOps Configuration
│   ├── bootstrap/
│   │   └── root.yaml          # App-of-apps root
│   ├── infrastructure/        # Platform components
│   └── tenants/               # Application namespaces
│       └── banking-core/      # Sample tenant
│
├── imladris-service-template/  # 🚀 Service Starter Kit
│   ├── main.go                # Go HTTP server
│   ├── Dockerfile             # Distroless container
│   └── k8s/                   # Kubernetes manifests
│
├── terraform/                  # 🔐 Security Engine (Optional)
│   └── eks-cilium-tetragon.tf # eBPF runtime security
│
├── lambda/                     # ⚡ Serverless Functions
│   └── drift_enforcement_lambda.py
│
└── k8s/                        # ☸️ Kubernetes Policies
    ├── fluent-bit/            # Logging configuration
    └── tetragon-policies/     # eBPF security policies
```

---

## 🔑 Key Design Decisions

### 1. Why VPC Lattice over Service Mesh?

| Consideration | VPC Lattice | Istio/Linkerd |
|--------------|-------------|---------------|
| **Infrastructure** | AWS-managed, zero pods | Sidecar per pod |
| **IAM Integration** | Native | Requires custom setup |
| **Operational Overhead** | Minimal | High |
| **Cost** | Pay per request | Compute for sidecars |
| **Banking Fit** | ✅ AWS-native compliance | ⚠️ Additional audit scope |

**Decision**: VPC Lattice provides service mesh capabilities with native IAM authentication and zero operational overhead.

### 2. Why Fargate-Only (No EC2)?

| Consideration | Fargate | EC2 Node Groups |
|--------------|---------|-----------------|
| **Patching** | AWS-managed | Customer responsibility |
| **SSH Access** | Impossible | Possible attack vector |
| **Compliance** | Simplified | Additional controls needed |
| **Blast Radius** | Pod-level isolation | Node-level sharing |
| **Cost Predictability** | Per-pod | Capacity planning needed |

**Decision**: Fargate eliminates persistent compute, reducing attack surface and compliance scope.

### 3. Why OPA/Rego for Policy?

| Consideration | OPA/Conftest | Sentinel | CloudFormation Guard |
|--------------|--------------|----------|---------------------|
| **Vendor Lock-in** | None | HashiCorp | AWS |
| **Language** | Rego (declarative) | Sentinel | YAML-like |
| **Ecosystem** | Broad (K8s, Terraform, etc.) | Terraform only | CloudFormation only |
| **Testing** | Built-in | Limited | Basic |

**Decision**: OPA provides vendor-neutral, testable policies across the entire stack.

### 4. Why GitOps with ArgoCD?

| Consideration | ArgoCD | Flux | Jenkins |
|--------------|--------|------|---------|
| **Audit Trail** | Git history | Git history | Build logs |
| **Drift Detection** | Continuous | Continuous | Manual |
| **Rollback** | Git revert | Git revert | Rebuild |
| **UI** | Rich dashboard | CLI-focused | Complex |
| **Multi-tenancy** | Projects/RBAC | Namespaces | Folders |

**Decision**: ArgoCD provides enterprise features with strong multi-tenant support.

---

## 🛡️ Security Model

### Zero Trust Principles Applied

| Principle | Implementation |
|-----------|---------------|
| **Never Trust, Always Verify** | IAM authentication on all service calls via VPC Lattice |
| **Least Privilege** | Minimal IAM policies, no wildcards |
| **Assume Breach** | Network segmentation, no lateral movement |
| **Verify Explicitly** | mTLS everywhere, no plaintext |
| **Limit Blast Radius** | Fargate pod isolation, namespace separation |

### Automated Compliance Pipeline

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Terraform  │───▶│   Conftest   │───▶│  AWS Config  │───▶│  EventBridge │
│    Plan      │    │  (Pre-Apply) │    │ (Post-Apply) │    │   (Detect)   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────┬───────┘
                                                                    │
                    ┌──────────────┐    ┌──────────────┐           │
                    │    Alert     │◀───│     SSM      │◀──────────┘
                    │   (SNS)      │    │  (Remediate) │
                    └──────────────┘    └──────────────┘
```

### Policies Enforced

| Policy | Description | Enforcement |
|--------|-------------|-------------|
| `deny-public-ingress` | Block 0.0.0.0/0 on all ports | Pre-apply (Conftest) |
| `enforce-fargate` | No EC2 instances allowed | Pre-apply (Conftest) |
| `require-vpc-lattice` | Services must use Lattice | Pre-apply (Conftest) |
| `restricted-ssh` | No SSH security group rules | Post-apply (AWS Config) |
| `s3-public-read` | No public S3 buckets | Post-apply (AWS Config) |

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | >= 1.0 | Infrastructure provisioning |
| AWS CLI | >= 2.31 | AWS authentication |
| kubectl | >= 1.28 | Kubernetes management |
| Conftest | >= 0.46 | Policy validation |

### Deployment

```bash
# 1. Clone repository
git clone https://github.com/ZEZE1020/imladris-project.git
cd imladris-project

# 2. Configure AWS credentials
aws configure

# 3. Deploy infrastructure
cd imladris-platform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

terraform init
terraform plan
terraform apply

# 4. Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name imladris-demo-cluster

# 5. Deploy GitOps
cd ../imladris-gitops
kubectl apply -f bootstrap/root.yaml
```

### Validate Policies

```bash
# Generate Terraform plan
cd imladris-platform
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Run policy checks
cd ../imladris-governance
conftest test ../imladris-platform/tfplan.json -p policies/terraform/
```

---

## 💰 Cost Estimation

### Monthly Costs (Approximate)

| Service | Configuration | Monthly Cost |
|---------|--------------|--------------|
| EKS Control Plane | 1 cluster | $73 |
| EKS Fargate | 3 pods (0.5 vCPU, 1GB) | $30-50 |
| VPC Endpoints | 5 Interface × 3 AZs | $110 |
| VPC Lattice | Service Network + Services | $50 |
| CloudWatch | Logs + Metrics | $10-20 |
| S3 | Config + Logs | $5 |
| KMS | 2 keys | $2 |

**Total Estimate**: **$280-350/month**

> 💡 For demos: Deploy, record, destroy within 1 hour = ~$2-5

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Setup Guide](docs/setup/SETUP.md) | Complete installation instructions |
| [AWS Setup](docs/setup/AWS-SETUP-GUIDE.md) | AWS-specific configuration |
| [Deployment](docs/DEPLOYMENT.md) | Deployment procedures |
| [RBAC Design](docs/architecture/RBAC-DESIGN.md) | Access control architecture |

---

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run policy checks (`conftest test`)
4. Run `terraform validate`
5. Commit changes (`git commit -m 'feat: add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- AWS Well-Architected Framework
- NIST Zero Trust Architecture (SP 800-207)
- Open Policy Agent community
- ArgoCD project

---

<p align="center">
  <b>Built for the financial services industry where security is not optional.</b>
</p>
