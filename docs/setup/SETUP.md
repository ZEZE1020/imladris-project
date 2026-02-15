# Imladris Setup Guide

Complete instructions for setting up the Imladris platform from scratch.

## Prerequisites

Install required tools on your machine:

```bash
# Terraform
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Conftest
curl -L https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_linux_x86_64.tar.gz | tar xz
sudo mv conftest /usr/local/bin/

# ArgoCD CLI (optional, but recommended)
curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
chmod +x argocd
sudo mv argocd /usr/local/bin/
```

Verify installations:

```bash
terraform version      # Should be >= 1.0
aws --version         # Should be >= 2.31
kubectl version       # Should be >= 1.28
conftest --version    # Should be >= 0.46
```

## Step 1: Prepare AWS Environment

### Create AWS Account and Configure Access

1. Have AWS account with appropriate permissions (Admin or Power User)
2. Create IAM user for Terraform deployment
3. Generate access key and secret key

Configure AWS CLI:

```bash
aws configure
# Enter AWS Access Key ID
# Enter AWS Secret Access Key
# Enter default region (e.g., us-east-1)
# Enter default output format (json)
```

### Verify AWS Access

```bash
aws sts get-caller-identity
# Should show your AWS account information
```

### Set Environment Variables

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=default
```

## Step 2: Clone Repository

```bash
git clone https://github.com/ZEZE1020/imladris-project.git
cd imladris-project
```

## Step 3: Deploy Infrastructure

### Configure Terraform Variables

```bash
cd imladris-platform
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your values
nano terraform.tfvars
```

Key variables to configure:

```hcl
aws_region          = "us-east-1"
cluster_name        = "imladris-dev"
environment         = "dev"
vpc_cidr            = "10.0.0.0/16"
instance_types      = ["t3.medium"]
desired_capacity    = 2
min_capacity        = 1
max_capacity        = 4
```

### Initialize Terraform

```bash
terraform init
```

This downloads required providers and modules.

### Validate Configuration

```bash
terraform validate
# Should output: Success! The configuration is valid.

terraform plan
# Review the planned changes
```

### Apply Configuration

```bash
terraform apply
# Review the plan and type 'yes' to proceed
# This takes approximately 15-20 minutes
```

Monitor the deployment:

```bash
# In another terminal, watch AWS CloudFormation events
aws cloudformation describe-stacks --stack-name imladris-dev-stack

# Or use AWS Console to track stack creation
```

### Verify Infrastructure

```bash
# Get outputs
terraform output

# Example outputs:
# cluster_name = imladris-dev
# cluster_endpoint = https://xxx.eks.amazonaws.com
# vpc_id = vpc-xxx
```

## Step 4: Configure kubectl

```bash
# Update kubeconfig
aws eks update-kubeconfig \
  --region us-east-1 \
  --name imladris-dev

# Verify cluster access
kubectl get nodes
# Should show Fargate nodes

kubectl get ns
# Should show default, kube-system, kube-public namespaces
```

## Step 5: Deploy Governance Policies

The governance policies validate all infrastructure changes. They're enforced at the Terraform level in CI/CD pipelines.

### Test Policies Locally

```bash
cd ../imladris-governance

# Run a test terraform plan
cd ../imladris-platform
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Validate against policies
cd ../imladris-governance
conftest verify --policy ./policies ../imladris-platform/tfplan.json
```

## Step 6: Deploy GitOps Platform

### Install ArgoCD

Create the namespace and install ArgoCD:

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for ArgoCD to be ready
kubectl rollout status deployment/argocd-server -n argocd

# Verify pods are running
kubectl get pods -n argocd
```

### Configure ArgoCD Access

Get the initial admin password:

```bash
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

Port forward to access ArgoCD UI:

```bash
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Access at https://localhost:8080
# Username: admin
# Password: (from above command)
```

### Deploy Imladris GitOps Configuration

```bash
cd imladris-gitops

# Apply bootstrap configuration
kubectl apply -f bootstrap/root.yaml

# Verify root application is created
kubectl get applications -n argocd
```

### Verify GitOps Deployment

```bash
# Check ArgoCD Application status
argocd app list

# Watch argocd-server logs
kubectl logs -f deployment/argocd-server -n argocd
```

## Step 7: Verify All Components

### Check Infrastructure

```bash
# VPC
aws ec2 describe-vpcs --query 'Vpcs[?Tags[?Value==`imladris-dev`]]'

# EKS Cluster
aws eks describe-cluster --name imladris-dev --query 'cluster.[name,status]'

# VPC Lattice (if configured)
aws vpc-lattice list-service-networks
```

### Check Kubernetes

```bash
# Get all namespaces
kubectl get namespaces

# Get all resources in banking-core namespace
kubectl get all -n banking-core

# Check network policies
kubectl get networkpolicies -n banking-core

# Check Fargate profile status
aws eks describe-fargate-profile \
  --cluster-name imladris-dev \
  --fargate-profile-name imladris-profile \
  --query 'fargateProfile.[fargateProfileName,status]'
```

### Check ArgoCD

```bash
# List applications
argocd app list

# Get application status
argocd app get root

# Watch sync activity
argocd app watch root
```

### Test Zero Trust Networking

```bash
# Verify no internet gateway
aws ec2 describe-internet-gateways \
  --filters "Name=attachment.vpc-id,Values=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)"
# Should return empty

# Check VPC Lattice services
aws vpc-lattice list-services

# Check security groups (should have no 0.0.0.0/0)
aws ec2 describe-security-groups --query 'SecurityGroups[?VpcId==`vpc-xxx`]'
```

## Step 8: Deploy Your First Service

Use the service template to deploy an application:

```bash
# Clone the service template
git clone https://github.com/ZEZE1020/imladris-service-template.git my-banking-service
cd my-banking-service

# Customize service name
export SERVICE_NAME="account-service"
export NAMESPACE="banking-core"

find . -name "*.yaml" -o -name "*.go" | \
  xargs sed -i "s/banking-core-service/$SERVICE_NAME/g"

# Push to trigger CI/CD
git add .
git commit -m "Initialize account service"
git push origin main

# Watch deployment in ArgoCD
argocd app watch $SERVICE_NAME
```

## Cleanup

To remove all infrastructure and costs:

```bash
# Delete GitOps resources
cd imladris-gitops
kubectl delete -f bootstrap/root.yaml

# Uninstall ArgoCD
kubectl delete namespace argocd

# Destroy infrastructure
cd ../imladris-platform
terraform destroy
# Type 'yes' to confirm
```

## Troubleshooting

### Terraform Errors

```bash
# Validate configuration
terraform validate

# Check state
terraform state list

# Refresh state
terraform refresh

# Format code
terraform fmt -recursive
```

### kubectl Issues

```bash
# Check kubeconfig
kubectl config view

# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name imladris-dev

# Test cluster access
kubectl auth can-i get pods --all-namespaces
```

### ArgoCD Issues

```bash
# Check ArgoCD logs
kubectl logs -f deployment/argocd-server -n argocd
kubectl logs -f deployment/argocd-controller-manager -n argocd

# Check ArgoCD config
kubectl get cm argocd-cm -n argocd -o yaml

# Restart ArgoCD
kubectl rollout restart deployment/argocd-server -n argocd
```

### Policy Validation Issues

```bash
# Check policies syntax
opa test policies/terraform/

# Debug policy evaluation
conftest verify -vv --policy policies/ tfplan.json

# Generate sample data for testing
terraform show -json tfplan > test-data/plan.json
```

## Next Steps

1. Review [DEPLOYMENT.md](./DEPLOYMENT.md) for service deployment procedures
2. Configure CI/CD pipelines to run policy validation
3. Set up monitoring and alerting with Prometheus and Grafana
4. Implement backup and disaster recovery procedures
5. Configure IAM Identity Center for centralized access control
