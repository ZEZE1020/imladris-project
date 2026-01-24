# Imladris Governance

Policy-as-Code definitions enforcing security and compliance across the platform.

## Overview

Uses Open Policy Agent (OPA) and Conftest to validate infrastructure against security policies:

- Prevents public ingress from 0.0.0.0/0 on all ports
- Requires VPC Lattice for all service communication
- Enforces Fargate-only compute (prohibits EC2)
- Mandates encryption for all communications

## Policies

### 1. Deny Public Ingress (deny-public-ingress.rego)

Blocks any security group from allowing public access:

- SSH (port 22) from 0.0.0.0/0
- HTTP (port 80) from 0.0.0.0/0
- HTTPS (port 443) except for VPC Lattice services
- RDP (port 3389) from 0.0.0.0/0
- All ports (0-65535) from 0.0.0.0/0

### 2. Require VPC Lattice (require-vpc-lattice.rego)

Enforces service mesh usage:

- All VPC Lattice services must be in a service network
- Services must use AWS_IAM authentication
- Listeners must use HTTPS for encryption
- Discourages public load balancers

### 3. Enforce Fargate (enforce-fargate.rego)

Prevents non-compliant compute resources:

- Blocks aws_instance resources (no EC2)
- Blocks aws_eks_node_group resources
- Blocks aws_autoscaling_group resources
- Requires Fargate profiles in private subnets

## Installation

```bash
# Install Conftest
curl -L https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_linux_x86_64.tar.gz | tar xz
sudo mv conftest /usr/local/bin

# Optional: Install OPA for policy testing
curl -L https://github.com/open-policy-agent/opa/releases/latest/download/opa_linux_amd64 -o opa
chmod +x opa
sudo mv opa /usr/local/bin
```

## Usage

### Validate Terraform Plans

```bash
# Generate plan
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Run policy validation
conftest verify --policy ./policies tfplan.json
```

### CI/CD Integration

Add to your pipeline:

```bash
# Plan and validate
terraform plan -out=tfplan -detailed-exitcode
terraform show -json tfplan > tfplan.json

# Check policies - fail on violations
conftest verify --policy ./imladris-governance/policies tfplan.json
if [ $? -ne 0 ]; then
  echo "Policy violations found"
  exit 1
fi

# Safe to apply
terraform apply tfplan
```

## Policy Development

### Test Policies

```bash
# Test policy rules
opa test policies/terraform/

# Test with sample Terraform plan
conftest verify --policy policies/ test-data/compliant-plan.json
conftest verify --policy policies/ test-data/violation-plan.json
```

### Policy Structure

```rego
package terraform.category

import rego.v1

# Deny rule (hard failure)
deny contains msg if {
    # condition logic
    msg := "VIOLATION: description"
}

# Warn rule (advisory)
warn contains msg if {
    # condition logic
    msg := "WARNING: description"
}
```

## Compliance Matrix

| Control | Policy | Description |
|---------|--------|-------------|
| Network Security | deny-public-ingress | No public inbound access |
| Service Mesh | require-vpc-lattice | All services use Lattice |
| Compute Security | enforce-fargate | Fargate only, no EC2 |
| Encryption | require-vpc-lattice | HTTPS mandatory |
| Access Control | require-vpc-lattice | IAM authentication required |

## Exceptions

Rare exceptions can be configured in `conftest.yaml`:

```yaml
exceptions:
  - policy: "terraform.security.deny[_]"
    resources:
      - "aws_vpclattice_service.health_check"
    conditions:
      - "contains(message, 'health check')"
```

Document all exceptions thoroughly.

## Integration

These policies validate:

- Terraform plans in CI/CD pipelines
- Infrastructure changes before deployment
- Kubernetes manifests via OPA Gatekeeper
- Container images at build time
