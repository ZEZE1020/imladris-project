# Zero Trust AWS Environment - User Management
# 5 Users with Role-Based Access Control

## User Roles and Permissions

### 1. Financial Analyst (FinOps)
**User**: sarah.finops@imladris.bank
**Role**: Cost optimization, billing analysis, resource governance
**Permissions**:
- Read-only access to all AWS resources
- Full access to Cost Explorer, Billing, Budgets
- CloudWatch metrics and dashboards
- Resource tagging enforcement
- No deployment permissions

### 2. DevOps Engineer 1 (Senior)
**User**: alex.devops@imladris.bank  
**Role**: Platform management, infrastructure deployment
**Permissions**:
- Full Terraform deployment access
- EKS cluster administration
- ArgoCD management
- AWS Config rule management
- Emergency break-glass access

### 3. DevOps Engineer 2 (Junior)
**User**: jamie.devops@imladris.bank
**Role**: Monitoring, incident response, limited infrastructure
**Permissions**:
- Read-only infrastructure access
- CloudWatch logs and metrics
- ArgoCD application sync
- Limited EKS troubleshooting
- No Terraform apply permissions

### 4. Developer 1 (Backend)
**User**: mike.dev@imladris.bank
**Role**: Banking service development, API management
**Permissions**:
- Deploy to banking-core namespace
- Read application logs and metrics
- ECR push/pull for banking services
- Limited kubectl access
- No infrastructure changes

### 5. Developer 2 (Frontend)
**User**: lisa.dev@imladris.bank
**Role**: Frontend development, UI services
**Permissions**:
- Deploy to banking-ui namespace
- Read application logs and metrics  
- ECR push/pull for UI services
- Limited kubectl access
- No infrastructure changes

## Zero Trust Principles Implementation

### Network Security
- No public subnets or internet gateways
- VPC Lattice for all service communication
- Default-deny network policies
- Encrypted traffic only (TLS 1.3)

### Identity & Access
- AWS IAM Identity Center (SSO)
- Multi-factor authentication required
- Just-in-time access with session limits
- Principle of least privilege

### Runtime Security
- Fargate-only compute (no EC2 instances)
- Container image scanning with Trivy
- Runtime threat detection with Falco
- Immutable infrastructure

### Automated Remediation
- AWS Config rules with auto-remediation
- EventBridge + Lambda for incident response
- Automatic security group lockdown
- Policy violation auto-rollback