# Zero Trust EKS Access Patterns

## Why Can't I Access the Cluster?

The EKS cluster has **private endpoint only** - this is intentional Zero Trust design:

```
endpoint_private_access = true
endpoint_public_access  = false  # No internet access to API
```

This means:
- ❌ Cannot `kubectl` from your laptop
- ❌ Cannot access from AWS CloudShell
- ❌ No public IP for the Kubernetes API
- ✅ Only accessible from within the VPC

## How to Deploy Applications

### Pattern 1: GitOps with ArgoCD (Recommended)

ArgoCD runs **inside** the cluster and pulls from Git:

```
Developer → git push → GitHub → ArgoCD (in-cluster) → Deploys
```

**Setup:**
1. Bootstrap ArgoCD during initial Terraform apply (via Lambda or user-data)
2. Configure ArgoCD to watch your Git repository
3. All deployments happen via Git commits

### Pattern 2: CI/CD Runner in VPC

Deploy a GitHub Actions self-hosted runner inside the VPC:

```
GitHub Actions → Runner (in VPC) → kubectl → EKS
```

**Setup:**
1. Deploy EC2 or Fargate task with GitHub runner
2. Runner has VPC network access to EKS
3. GitHub Actions workflows use the self-hosted runner

### Pattern 3: VPN/Direct Connect (Enterprise)

Connect your corporate network to the VPC:

```
Developer Laptop → VPN → VPC → EKS
```

**Setup:**
1. AWS Client VPN or Site-to-Site VPN
2. Or AWS Direct Connect for dedicated connection
3. Developers connect to VPN, then use kubectl

### Pattern 4: AWS Cloud9 IDE

Browser-based IDE running inside your VPC:

```
Browser → Cloud9 (in VPC) → EKS
```

**Setup:**
1. Deploy Cloud9 environment in private subnet
2. Access via AWS Console
3. Use kubectl from Cloud9 terminal

### Pattern 5: SSM Session Manager

Connect to a bastion or pod via Systems Manager:

```
AWS Console → SSM → Container/EC2 → kubectl
```

## Initial Bootstrap

For the very first deployment (ArgoCD itself), use one of these:

### Option A: Terraform with Lambda

```hcl
resource "aws_lambda_function" "eks_bootstrap" {
  function_name = "eks-bootstrap"
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.eks_security_group_id]
  }
  # Runs kubectl apply for ArgoCD
}
```

### Option B: User Data Script

If using an initial EC2 instance:

```bash
#!/bin/bash
aws eks update-kubeconfig --name imladris-demo-cluster
kubectl apply -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

### Option C: AWS CodeBuild in VPC

```yaml
# buildspec.yml
phases:
  install:
    commands:
      - aws eks update-kubeconfig --name imladris-demo-cluster
  build:
    commands:
      - kubectl apply -f argocd/
```

## Security Benefits

This architecture provides:

1. **No attack surface** - No public API endpoint to exploit
2. **Network isolation** - All traffic stays in VPC
3. **Audit trail** - All access through controlled channels
4. **Least privilege** - Only CI/CD has deploy access

## For Demo/Testing

If you need temporary access for testing:

1. **Temporarily enable public endpoint** (not recommended for production)
2. **Deploy Cloud9** in the VPC
3. **Use AWS Console** EKS features (limited)

The inability to access from outside the VPC **proves the Zero Trust architecture is working**.
