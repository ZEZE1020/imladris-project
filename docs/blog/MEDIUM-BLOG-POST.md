# Building a Zero Trust AWS Platform for Financial Services: A Complete Guide

*How I built a production-ready, compliance-first infrastructure with automated security remediation using Terraform, EKS, and AWS native services*

![Zero Trust Architecture Banner](./images/banner.png)

---

## Introduction

In financial services, security isn't a feature—it's the foundation. After years of building traditional perimeter-based architectures, I decided to challenge myself: **Can I build a truly Zero Trust AWS environment that's both secure AND developer-friendly?**

The answer is yes, and in this post, I'll walk you through exactly how I built **Imladris Platform**—a complete Zero Trust AWS environment featuring:

- 🔒 **Zero public endpoints** (not even a NAT Gateway)
- 🚀 **Serverless compute** with EKS Fargate
- 🔐 **Identity-based access** with AWS IAM Identity Center
- ⚡ **Automated security remediation** (self-healing infrastructure)
- 📊 **Continuous compliance monitoring** with AWS Config

> **Why "Imladris"?** Named after Rivendell from The Lord of the Rings—a hidden sanctuary protected from outside threats. Perfect for a Zero Trust architecture!

---

## The Problem with Traditional Cloud Security

Most AWS architectures look like this:

```
Internet → IGW → Public Subnet → NAT → Private Subnet → Workloads
```

This creates multiple attack vectors:
- Public subnets with internet-facing resources
- NAT Gateways that could be misconfigured
- Security groups as the only line of defense
- Manual remediation of security violations

**Zero Trust flips this model**: Trust nothing, verify everything, and assume breach.

---

## Architecture Overview

Here's what we're building:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS Account                                  │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    VPC (10.0.0.0/16)                          │  │
│  │                    NO Internet Gateway                         │  │
│  │                                                                │  │
│  │  ┌─────────────────┐    ┌─────────────────┐                   │  │
│  │  │ Private Subnet  │    │ Private Subnet  │                   │  │
│  │  │   us-east-1a    │    │   us-east-1b    │                   │  │
│  │  │  10.0.0.0/24    │    │  10.0.1.0/24    │                   │  │
│  │  └────────┬────────┘    └────────┬────────┘                   │  │
│  │           │                      │                             │  │
│  │           └──────────┬───────────┘                             │  │
│  │                      │                                         │  │
│  │  ┌───────────────────┴───────────────────┐                    │  │
│  │  │         EKS Fargate Cluster           │                    │  │
│  │  │      (Private Endpoint Only)          │                    │  │
│  │  │                                       │                    │  │
│  │  │  ┌─────────┐  ┌─────────┐            │                    │  │
│  │  │  │ Pod     │  │ Pod     │            │                    │  │
│  │  │  │(Fargate)│  │(Fargate)│            │                    │  │
│  │  │  └─────────┘  └─────────┘            │                    │  │
│  │  └───────────────────────────────────────┘                    │  │
│  │                      │                                         │  │
│  │  ┌───────────────────┴───────────────────┐                    │  │
│  │  │           VPC Lattice                  │                    │  │
│  │  │      Service-to-Service Mesh           │                    │  │
│  │  └───────────────────────────────────────┘                    │  │
│  │                                                                │  │
│  │  VPC Endpoints: ECR, S3, EKS (No Internet Required)           │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  AWS Config  │→ │ EventBridge  │→ │ Lambda/SSM   │              │
│  │  (Monitor)   │  │  (Detect)    │  │ (Remediate)  │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision | Why |
|----------|-----|
| **No Internet Gateway** | Eliminates the largest attack surface |
| **Fargate Only** | No EC2 instances to patch or secure |
| **VPC Endpoints** | Private connectivity to AWS services |
| **VPC Lattice** | Service mesh without sidecars |
| **Private EKS Endpoint** | API server unreachable from internet |

---

## Phase 1: Zero Trust Networking

The foundation of our architecture is a VPC with **no path to the internet**.

### Terraform Configuration

```hcl
# VPC with private subnets only
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
  }
}

# Private subnets - NO public subnets exist
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name                              = "${var.project_name}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# NO Internet Gateway - this is intentional!
# NO NAT Gateway - workloads use VPC Endpoints instead
```

### VPC Endpoints for AWS Services

Without internet access, we need private paths to AWS services:

```hcl
# S3 Gateway Endpoint (free)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# ECR API Endpoint (for docker pull)
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}

# EKS Endpoint (for kubectl)
resource "aws_vpc_endpoint" "eks" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.eks"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}
```

**Cost Note**: Interface endpoints cost ~$7.50/month each. We use 3 (ECR API, ECR DKR, EKS) = ~$22.50/month for complete network isolation.

---

## Phase 2: Serverless Kubernetes with EKS Fargate

Why Fargate over EC2 nodes?

| EC2 Nodes | Fargate |
|-----------|---------|
| You patch the OS | AWS patches everything |
| Instance-level security | Pod-level isolation |
| Shared kernel | Dedicated microVM per pod |
| Over-provisioning waste | Pay per pod |

### EKS Configuration

```hcl
resource "aws_eks_cluster" "main" {
  name     = "${var.project_name}-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = "1.28"

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false  # 🔒 Private only!
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  # Encrypt secrets at rest
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api", "audit", "authenticator", 
    "controllerManager", "scheduler"
  ]
}

# Fargate profile - runs ALL pods on Fargate
resource "aws_eks_fargate_profile" "main" {
  cluster_name           = aws_eks_cluster.main.name
  fargate_profile_name   = "${var.project_name}-fargate-profile"
  pod_execution_role_arn = aws_iam_role.fargate_pod_execution_role.arn
  subnet_ids             = var.private_subnet_ids

  selector {
    namespace = "default"
  }

  selector {
    namespace = "kube-system"
  }
}
```

---

## Phase 3: Identity-Based Access with IAM Identity Center

Instead of shared credentials or long-lived access keys, we use IAM Identity Center with role-based access:

### User Roles

| Role | Users | Access Level |
|------|-------|--------------|
| **FinOps Analyst** | Sarah | Cost Explorer, Budgets (Read-only) |
| **Senior DevOps** | Alex | Full EKS, ECR, networking |
| **Junior DevOps** | Jamie | EKS read, ECR push only |
| **Backend Developer** | Mike | ECR, CloudWatch, limited EKS |
| **Frontend Developer** | Lisa | ECR, CloudWatch, S3 static assets |

### Terraform Configuration

```hcl
# Create user in Identity Center
resource "aws_identitystore_user" "finops_analyst" {
  identity_store_id = local.identity_store_id

  display_name = "Sarah Chen"
  user_name    = "sarah.finops"

  name {
    given_name  = "Sarah"
    family_name = "Chen"
  }

  emails {
    value   = var.finops_email
    primary = true
  }
}

# Permission set with least privilege
resource "aws_ssoadmin_permission_set" "finops_analyst" {
  name             = "FinOpsAnalyst"
  description      = "Read-only access to billing and cost management"
  instance_arn     = local.identity_center_instance_arn
  session_duration = "PT4H"  # 4-hour sessions
}

resource "aws_ssoadmin_permission_set_inline_policy" "finops_policy" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.finops_analyst.arn

  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ce:*",           # Cost Explorer
          "budgets:View*",  # Budgets read-only
          "cur:Describe*"   # Cost reports
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

## Phase 4: Automated Security Remediation

This is where it gets interesting. Instead of alerting humans about security violations, we **automatically fix them**.

### The Flow

```
Security Violation → AWS Config → EventBridge → Lambda/SSM → Auto-Remediate
```

### AWS Config Rules

We monitor 6 critical security controls:

```hcl
# Detect SSH open to the world
resource "aws_config_config_rule" "restricted_ssh" {
  name = "${var.project_name}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.recorder]
}

# Detect public S3 buckets
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "${var.project_name}-s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

# Detect public EKS endpoints
resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  name = "${var.project_name}-eks-endpoint-no-public-access"

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }
}
```

### SSM Automation for SSH Remediation

```yaml
schemaVersion: '0.3'
description: 'Automatically revoke SSH access (port 22) from 0.0.0.0/0'
assumeRole: '{{ AutomationAssumeRole }}'
parameters:
  SecurityGroupId:
    type: String
    description: 'The ID of the security group to remediate'
  AutomationAssumeRole:
    type: String
    description: 'The ARN of the role to assume'
mainSteps:
  - name: RevokeSSHAccess
    action: 'aws:executeAwsApi'
    inputs:
      Service: ec2
      Api: RevokeSecurityGroupIngress
      GroupId: '{{ SecurityGroupId }}'
      IpPermissions:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          IpRanges:
            - CidrIp: '0.0.0.0/0'
```

### Lambda for Complex Remediation

```python
import boto3
import json

def lambda_handler(event, context):
    """
    Handles AWS Config compliance change events and triggers remediation.
    """
    detail = event.get('detail', {})
    compliance_type = detail.get('newEvaluationResult', {}).get('complianceType')
    
    if compliance_type != 'NON_COMPLIANT':
        return {'statusCode': 200, 'body': 'Resource is compliant'}
    
    resource_type = detail.get('resourceType')
    resource_id = detail.get('resourceId')
    
    # Route to appropriate remediation
    if resource_type == 'AWS::EC2::SecurityGroup':
        return remediate_security_group(resource_id)
    elif resource_type == 'AWS::S3::Bucket':
        return remediate_s3_bucket(resource_id)
    
    return {'statusCode': 200, 'body': f'No remediation for {resource_type}'}

def remediate_security_group(sg_id):
    """Remove SSH access from 0.0.0.0/0"""
    ec2 = boto3.client('ec2')
    
    try:
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        return {'statusCode': 200, 'body': f'Remediated {sg_id}'}
    except Exception as e:
        return {'statusCode': 500, 'body': str(e)}
```

---

## Phase 5: VPC Lattice Service Mesh

VPC Lattice provides service-to-service communication without sidecars:

```hcl
# Service Network (like a service mesh control plane)
resource "aws_vpclattice_service_network" "main" {
  name      = "${var.project_name}-service-network"
  auth_type = "AWS_IAM"  # All traffic requires IAM auth
}

# Associate VPC with Service Network
resource "aws_vpclattice_service_network_vpc_association" "main" {
  vpc_identifier             = aws_vpc.main.id
  service_network_identifier = aws_vpclattice_service_network.main.id
}

# EKS API as a Lattice service
resource "aws_vpclattice_service" "eks_api" {
  name      = "${var.project_name}-eks-api"
  auth_type = "AWS_IAM"
}
```

---

## Results

After deploying this architecture:

### Security Posture
- ✅ **Zero public IP addresses** in the entire infrastructure
- ✅ **No SSH access** possible (no bastion, no EC2)
- ✅ **Automatic remediation** of security violations
- ✅ **Encryption everywhere** (KMS for EKS secrets, S3 SSE)

### Cost Breakdown (Estimated Monthly)

| Service | Cost |
|---------|------|
| EKS Control Plane | $73 |
| Fargate (minimal workload) | ~$20 |
| VPC Endpoints (3 Interface) | $22.50 |
| VPC Lattice | ~$5 |
| AWS Config | ~$3 |
| CloudWatch Logs | ~$5 |
| **Total** | **~$130/month** |

### Compliance
- SOC 2 Type II aligned
- PCI-DSS network segmentation
- NIST 800-53 controls

---

## Lessons Learned

### 1. VPC Endpoints Are Essential
Without internet access, you need endpoints for EVERY AWS service your workloads touch. Start with: ECR, S3, EKS, CloudWatch Logs.

### 2. Fargate CoreDNS Needs Special Handling
CoreDNS on Fargate requires a Fargate profile selector for `kube-system` namespace.

### 3. IAM Identity Center Has Tiers
The free tier (account-level) doesn't support permission sets. You need AWS Organizations for full RBAC.

### 4. Test Remediation Before Production
Create a test security group, open SSH, and watch it auto-remediate. Satisfying!

---

## Repository Structure

```
imladris-project/
├── imladris-platform/          # Main Terraform
│   ├── modules/
│   │   ├── networking/         # VPC, endpoints, Lattice
│   │   ├── compute/            # EKS, Fargate, Identity Center
│   │   └── governance/         # Config, remediation, ECR
│   ├── main.tf
│   └── variables.tf
├── imladris-gitops/            # ArgoCD configurations
├── imladris-governance/        # OPA policies
├── k8s/                        # Kubernetes manifests
│   └── tetragon-policies/      # Runtime security
└── lambda/                     # Remediation functions
```

---

## What's Next?

In Part 2, I'll cover:
- **Runtime Security** with Tetragon (eBPF-based enforcement)
- **GitOps** with ArgoCD for continuous deployment
- **OPA Policies** for infrastructure as code validation

---

## Try It Yourself

The complete code is available on GitHub:

```bash
git clone https://github.com/yourusername/imladris-project
cd imladris-project/imladris-platform
terraform init
terraform plan
terraform apply
```

---

## Connect With Me

Have questions about Zero Trust architectures? Let's connect:
- **LinkedIn**: [[linkedIn.com/in/ogembo-godfrey](https://www.linkedin.com/in/ogembo-godfrey/)]
- **Twitter**: [https://x.com/ogembo_godfrey]
- **GitHub**: [github.com/ZEZE1020]

---

*If you found this helpful, please give it a clap 👏 and follow for Part 2!*

**Tags**: #AWS #ZeroTrust #Terraform #Kubernetes #CloudSecurity #FinancialServices #DevSecOps
