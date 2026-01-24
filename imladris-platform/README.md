# Imladris Platform

Infrastructure as Code for zero trust AWS environment using Terraform.

## Overview

Provides complete AWS infrastructure with:
- Private VPC (10.0.0.0/16) with no internet gateway
- VPC Lattice service mesh for zero-trust communication
- EKS Fargate cluster for containerized workloads
- Self-healing governance through AWS Config, EventBridge, and SSM
- IAM Identity Center for centralized access control

## Architecture

The platform consists of three main Terraform modules:

### Networking Module
- Private-only VPC with no public routes
- VPC Lattice service network for service-to-service communication
- VPC endpoints for private access to AWS services (S3, ECR, etc.)
- Private subnets across multiple availability zones

### Governance Module
- AWS Config rules for continuous compliance monitoring
- EventBridge rules to trigger automated remediation
- SSM Automation documents for self-healing (e.g., SSH restriction remediation)
- CloudWatch logs for audit trails

### Compute Module
- EKS Fargate cluster with no EC2 node groups
- KMS encryption for secrets at rest
- IAM Identity Center integration for RBAC
- VPC Lattice service integration

## Self-Healing Infrastructure

The platform implements automatic remediation:

1. **Detection**: AWS Config evaluates resources against rules
2. **Trigger**: Non-compliance triggers EventBridge rule
3. **Remediation**: SSM Automation executes corrective action
4. **Verification**: Config re-evaluates compliance status

Example: If a security group allows SSH from 0.0.0.0/0, it is automatically reverted.

## Configuration

### Prerequisites
```bash
terraform >= 1.0
aws-cli >= 2.31
kubectl >= 1.28
```

### Variables

Copy `terraform.tfvars.example` to `terraform.tfvars`:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Key variables:
- `aws_region`: AWS region (e.g., us-east-1)
- `cluster_name`: EKS cluster name
- `environment`: Deployment environment (dev, staging, prod)
- `vpc_cidr`: VPC CIDR block (default: 10.0.0.0/16)

## Deployment

```bash
# Initialize Terraform
terraform init

# Review planned changes
terraform plan

# Apply configuration
terraform apply
```

### Post-Deployment

```bash
# Configure kubectl
aws eks update-kubeconfig --region <region> --name <cluster-name>

# Verify cluster access
kubectl get nodes

# Check infrastructure
terraform output
```

## Compliance Features

- No public endpoints or internet gateways
- KMS encryption for all secrets
- Comprehensive CloudWatch logging
- Automatic security violation remediation
- IAM Identity Center SSO integration
- VPC Lattice for encrypted service communication

## Zero Trust Principles

1. All services communicate via VPC Lattice with IAM authentication
2. No VPN access; only IAM Identity Center
3. Immutable Fargate compute with no persistent state
4. Continuous compliance monitoring and auto-remediation
5. Minimal permissions via least privilege access

## Modules

```
modules/
├── networking/
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── governance/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── automation/
│       └── remediate-ssh.yaml
└── compute/
    ├── main.tf
    ├── variables.tf
    └── outputs.tf
```

## Next Steps

1. Deploy infrastructure with Terraform
2. Configure [imladris-governance](../imladris-governance) policies
3. Set up [imladris-gitops](../imladris-gitops) for application deployment
4. Create services using [imladris-service-template](../imladris-service-template)