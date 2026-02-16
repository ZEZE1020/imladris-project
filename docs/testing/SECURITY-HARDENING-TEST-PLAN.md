# Imladris Security Hardening - Comprehensive Test Plan
## Post-Gemini Changes Validation

**Test Date**: February 2026  
**Version**: Security Hardening v1.0  
**Authors**: Platform Team  

---

## Table of Contents
1. [Pre-Test Prerequisites](#pre-test-prerequisites)
2. [Phase 1: Infrastructure Validation](#phase-1-infrastructure-validation)
3. [Phase 2: Per-User RBAC Testing](#phase-2-per-user-rbac-testing)
4. [Phase 3: Security Control Verification](#phase-3-security-control-verification)
5. [Phase 4: Negative Testing (Security Boundary Validation)](#phase-4-negative-testing)
6. [Phase 5: End-to-End Workflow Testing](#phase-5-end-to-end-workflow-testing)

---

## Pre-Test Prerequisites

### Infrastructure Requirements
- [ ] IAM Identity Center enabled and configured
- [ ] EKS cluster `imladris-dev-cluster` is running
- [ ] ArgoCD bootstrapped via CodeBuild
- [ ] All 5 users have received SSO invitations

### Test Accounts
> **Note:** The email addresses below are example placeholders. Replace them with actual test account emails in your environment before deployment.

| User | Email | Role | Permission Set |
|------|-------|------|----------------|
| sarah.finops | sarah.finops@example.com | FinOps Analyst | ImladrisFinOpsAnalyst |
| alex.devops | alex.devops@example.com | Senior DevOps | ImladrisSeniorDevOps |
| jamie.devops | jamie.devops@example.com | Junior DevOps | ImladrisJuniorDevOps |
| mike.dev | mike.dev@example.com | Backend Dev | ImladrisBackendDeveloper |
| lisa.dev | lisa.dev@example.com | Frontend Dev | ImladrisFrontendDeveloper |

### SSO Login URL
```
https://<identity-center-id>.awsapps.com/start
```

---

## Phase 1: Infrastructure Validation

### 1.1 Terraform Validation
```bash
# Run from imladris-platform directory
cd /home/ogembo/imladris-project/imladris-platform

# Validate configuration
terraform validate

# Plan changes (dry run)
terraform plan -out=test-plan.tfplan

# Check for any errors related to:
# - Missing variable references (vpc_cidr, aws_region, eks_cluster_name)
# - Security group rule changes
# - IAM policy syntax errors
```

**Expected Results:**
- [ ] No validation errors
- [ ] Plan shows expected changes
- [ ] No destroy actions for critical resources

### 1.2 EKS Cluster Access Verification
```bash
# As admin user, verify cluster is accessible
aws eks update-kubeconfig --name imladris-dev-cluster --region us-east-1

# Should fail from local machine (Zero Trust - private endpoint only)
kubectl get nodes
# Expected: Unable to connect to the server

# Run CodeBuild bootstrap to verify VPC-internal access
aws codebuild start-build --project-name imladris-eks-bootstrap --region us-east-1
```

### 1.3 Security Group Verification
```bash
# Verify EKS security group only allows port 443
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=imladris-dev-eks-cluster-*" \
  --query 'SecurityGroups[*].IpPermissions'
```

**Expected:** Only port 443 ingress from 10.0.0.0/16

---

## Phase 2: Per-User RBAC Testing

### 2.1 FinOps Analyst (Sarah Johnson)

**Login:** SSO Portal → ImladrisFinOpsAnalyst

#### Positive Tests (SHOULD WORK)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| FIN-01 | View Cost Explorer | AWS Console → Cost Explorer | Full access |
| FIN-02 | View Budgets | AWS Console → Budgets | Full access |
| FIN-03 | List EC2 Instances | `aws ec2 describe-instances` | Success |
| FIN-04 | View CloudWatch Metrics | AWS Console → CloudWatch | Read access |
| FIN-05 | View Resource Tags | `aws resourcegroupstaggingapi get-resources` | Success |

#### Negative Tests (SHOULD FAIL)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| FIN-N01 | Create IAM User | `aws iam create-user --user-name test` | Access Denied |
| FIN-N02 | Delete S3 Bucket | `aws s3 rb s3://any-bucket` | Access Denied |
| FIN-N03 | Modify Security Group | `aws ec2 authorize-security-group-ingress...` | Access Denied |
| FIN-N04 | Deploy to EKS | Via kubectl or ArgoCD | No access |

---

### 2.2 Senior DevOps (Alex Rodriguez)

**Login:** SSO Portal → ImladrisSeniorDevOps

#### Positive Tests (SHOULD WORK)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| SDEV-01 | View EKS Cluster | `aws eks describe-cluster --name imladris-dev-cluster` | Success |
| SDEV-02 | List IAM Roles | `aws iam list-roles` | Success |
| SDEV-03 | Get IAM Policy | `aws iam get-policy --policy-arn ...` | Success |
| SDEV-04 | Read Terraform State S3 | `aws s3 get-object --bucket imladris-...` | Success |
| SDEV-05 | Write to Terraform State S3 | `aws s3 put-object --bucket imladris-...` | Success |
| SDEV-06 | Pass Role to EKS | `aws iam pass-role` to EKS service | Success |
| SDEV-07 | Manage CloudWatch | `aws cloudwatch put-metric-alarm...` | Success |
| SDEV-08 | Manage AWS Config | `aws configservice describe-config-rules` | Success |

#### **CRITICAL Negative Tests (Security Hardening Validation)**
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| SDEV-N01 | **Create IAM User** | `aws iam create-user --user-name escalation-test` | **Access Denied** |
| SDEV-N02 | **Create IAM Role** | `aws iam create-role --role-name admin-role...` | **Access Denied** |
| SDEV-N03 | **Attach Admin Policy** | `aws iam attach-user-policy --policy-arn AdministratorAccess...` | **Access Denied** |
| SDEV-N04 | **Pass Role to Lambda** | `aws iam pass-role` to Lambda service | **Access Denied** |
| SDEV-N05 | **Read Unrelated S3** | `aws s3 cp s3://other-bucket/file .` | **Access Denied** |
| SDEV-N06 | **Create S3 Bucket** | `aws s3 mb s3://test-bucket-new` | **Access Denied** |
| SDEV-N07 | **Delete S3 Bucket** | `aws s3 rb s3://imladris-dev-config-...` | **Access Denied** |

```bash
# Privilege Escalation Test Script for Alex
#!/bin/bash
echo "=== Privilege Escalation Test ==="

# Test 1: Try to create an IAM user
aws iam create-user --user-name escalation-test-user 2>&1 | grep -q "AccessDenied" && echo "PASS: Cannot create IAM user" || echo "FAIL: Could create IAM user!"

# Test 2: Try to pass role to Lambda (should fail)
aws lambda create-function \
  --function-name escalation-test \
  --role arn:aws:iam::ACCOUNT:role/any-role \
  --runtime python3.9 \
  --handler lambda_function.handler \
  --zip-file fileb://dummy.zip 2>&1 | grep -q "AccessDenied" && echo "PASS: Cannot pass role to Lambda" || echo "FAIL: Could pass role to Lambda!"

# Test 3: Try to read from unrelated S3 bucket
aws s3 cp s3://some-other-bucket/test.txt . 2>&1 | grep -q "AccessDenied" && echo "PASS: Cannot read unrelated S3" || echo "FAIL: Could read unrelated S3!"
```

---

### 2.3 Junior DevOps (Jamie Chen)

**Login:** SSO Portal → ImladrisJuniorDevOps

#### Positive Tests (SHOULD WORK)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| JDEV-01 | Describe EKS | `aws eks describe-cluster...` | Success |
| JDEV-02 | View CloudWatch Logs | `aws logs describe-log-groups` | Success |
| JDEV-03 | View EC2 Instances | `aws ec2 describe-instances` | Success |
| JDEV-04 | View Config Rules | `aws configservice describe-config-rules` | Success |
| JDEV-05 | View ECR Images | `aws ecr describe-images...` | Success |

#### Negative Tests (SHOULD FAIL)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| JDEV-N01 | Create EC2 Instance | `aws ec2 run-instances...` | Access Denied |
| JDEV-N02 | Modify EKS | `aws eks update-cluster-config...` | Access Denied |
| JDEV-N03 | Delete Log Group | `aws logs delete-log-group...` | Access Denied |
| JDEV-N04 | Push to ECR | `docker push...` | Access Denied |

---

### 2.4 Backend Developer (Mike Thompson)

**Login:** SSO Portal → ImladrisBackendDeveloper

#### Positive Tests (SHOULD WORK)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| BDEV-01 | Access EKS API (banking-core) | Via ArgoCD/kubectl | Success |
| BDEV-02 | Push to banking-* ECR | `docker push .../banking-core:v1` | Success |
| BDEV-03 | View banking-core Logs | CloudWatch Logs | Success |
| BDEV-04 | Deploy to banking-core NS | ArgoCD sync | Success |

#### Negative Tests (SHOULD FAIL)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| BDEV-N01 | Deploy to banking-ui NS | ArgoCD/kubectl | Access Denied |
| BDEV-N02 | Push to banking-ui ECR | `docker push .../banking-ui:v1` | Access Denied |
| BDEV-N03 | Access infrastructure | `aws eks describe-cluster...` | Access Denied |
| BDEV-N04 | View FinOps data | Cost Explorer | Access Denied |

---

### 2.5 Frontend Developer (Lisa Wang)

**Login:** SSO Portal → ImladrisFrontendDeveloper

#### Positive Tests (SHOULD WORK)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| FDEV-01 | Access EKS API (banking-ui) | Via ArgoCD/kubectl | Success |
| FDEV-02 | Push to banking-ui ECR | `docker push .../banking-ui:v1` | Success |
| FDEV-03 | View banking-ui Logs | CloudWatch Logs | Success |
| FDEV-04 | Deploy to banking-ui NS | ArgoCD sync | Success |

#### Negative Tests (SHOULD FAIL)
| Test ID | Action | Command/Console | Expected Result |
|---------|--------|-----------------|-----------------|
| FDEV-N01 | Deploy to banking-core NS | ArgoCD/kubectl | Access Denied |
| FDEV-N02 | Push to banking-core ECR | `docker push .../banking-core:v1` | Access Denied |
| FDEV-N03 | Access infrastructure | `aws eks describe-cluster...` | Access Denied |
| FDEV-N04 | View Cost data | Cost Explorer | Access Denied |

---

## Phase 3: Security Control Verification

### 3.1 Network Security - EKS Port 443 Restriction

```bash
# Test 1: Verify security group configuration
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=*imladris*eks*" \
  --query 'SecurityGroups[].{Name:GroupName,Rules:IpPermissions}'

# Expected: Only ingress on port 443
# {
#   "FromPort": 443,
#   "ToPort": 443,
#   "IpProtocol": "tcp",
#   "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
# }

# Test 2: Attempt connection on other ports (from within VPC)
# This requires a test pod inside the cluster
kubectl run port-test --image=busybox --rm -it -- \
  nc -zv <eks-api-endpoint> 80
# Expected: Connection refused

kubectl run port-test --image=busybox --rm -it -- \
  nc -zv <eks-api-endpoint> 443
# Expected: Connection succeeded
```

### 3.2 Data Integrity - Config Bucket Protection

```bash
# Test: Attempt to destroy bucket with data
cd /home/ogembo/imladris-project/imladris-platform

# This should FAIL if bucket has data
terraform destroy -target=aws_s3_bucket.config

# Expected: Error - bucket is not empty, force_destroy = false
```

### 3.3 CodeBuild S3 Scope Restriction

```bash
# Test: Verify CodeBuild can only access imladris-* buckets
# Create test build that attempts to read from other bucket

# This should SUCCEED
aws s3 cp s3://imladris-dev-artifacts/test.txt . --profile codebuild-role

# This should FAIL
aws s3 cp s3://unrelated-bucket/secret.txt . --profile codebuild-role
# Expected: Access Denied
```

### 3.4 Supply Chain Security - Harbor Checksum Verification

```bash
# Test: Verify checksum validation works
# Temporarily modify checksum in harbor-setup.sh to wrong value
# Run the script and verify it FAILS

# Test script:
HARBOR_SHA256="wrong_checksum_value"
echo "$HARBOR_SHA256  harbor-offline-installer-v2.9.1.tgz" | sha256sum -c -
# Expected: FAILED - sha256sum mismatch
```

---

## Phase 4: Negative Testing (Security Boundary Validation)

### 4.1 Privilege Escalation Attempts

Run these tests as **alex.devops** (Senior DevOps):

```bash
#!/bin/bash
# privilege-escalation-test.sh

echo "=== Imladris Privilege Escalation Tests ==="
echo "Running as: $(aws sts get-caller-identity --query Arn --output text)"
echo ""

# Test 1: Create privileged IAM role
echo "Test 1: Attempting to create privileged IAM role..."
RESULT=$(aws iam create-role \
  --role-name EscalationTestRole \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' 2>&1)

if echo "$RESULT" | grep -q "AccessDenied"; then
  echo "✅ PASS: Cannot create IAM roles"
else
  echo "❌ FAIL: Was able to create IAM role!"
  aws iam delete-role --role-name EscalationTestRole 2>/dev/null
fi

# Test 2: Attach administrator policy
echo "Test 2: Attempting to attach admin policy..."
RESULT=$(aws iam attach-role-policy \
  --role-name AnyExistingRole \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>&1)

if echo "$RESULT" | grep -q "AccessDenied"; then
  echo "✅ PASS: Cannot attach admin policy"
else
  echo "❌ FAIL: Was able to attach admin policy!"
fi

# Test 3: Pass role to unauthorized service
echo "Test 3: Attempting to pass role to Lambda..."
RESULT=$(aws lambda create-function \
  --function-name EscalationTest \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT_ID:role/existing-role \
  --handler index.handler \
  --code S3Bucket=any-bucket,S3Key=any-key.zip 2>&1)

if echo "$RESULT" | grep -q "AccessDenied"; then
  echo "✅ PASS: Cannot pass role to Lambda"
else
  echo "❌ FAIL: Was able to pass role to Lambda!"
fi

# Test 4: Access data from unrelated S3 bucket
echo "Test 4: Attempting to read from unrelated S3 bucket..."
RESULT=$(aws s3 cp s3://some-other-account-bucket/data.txt /tmp/ 2>&1)

if echo "$RESULT" | grep -q "AccessDenied"; then
  echo "✅ PASS: Cannot access unrelated S3 buckets"
else
  echo "❌ FAIL: Was able to access unrelated S3 bucket!"
fi

echo ""
echo "=== Privilege Escalation Tests Complete ==="
```

### 4.2 Cross-Namespace Access Tests (Kubernetes)

```yaml
# test-cross-namespace-access.yaml
# Run as mike.dev (backend developer) - should fail to access banking-ui

apiVersion: v1
kind: Pod
metadata:
  name: cross-namespace-test
  namespace: banking-core
spec:
  containers:
  - name: test
    image: curlimages/curl
    command: ["sleep", "3600"]
---
# After pod is running:
# kubectl exec -it cross-namespace-test -n banking-core -- \
#   curl http://banking-ui-service.banking-ui.svc.cluster.local
# Expected: Network policy blocks access OR RBAC denies
```

---

## Phase 5: End-to-End Workflow Testing

> ⚠️ **WARNING: This phase includes intentionally creating security violations for testing.**
> 
> - **NEVER run these tests in production environments**
> - Requires proper change control and approval even in dev/test environments
> - Tests should only be executed in isolated, non-critical environments
> - Ensure you have rollback procedures ready before testing
> - Document all test activities for audit compliance

### 5.1 Complete GitOps Deployment Flow

**Scenario**: Backend developer (Mike) deploys a new version of banking-core

```
1. Mike pushes code to GitHub (banking-core repo)
2. CI/CD builds and pushes image to ECR (banking-core:v2)
3. Mike updates banking-core deployment in imladris-gitops repo
4. ArgoCD detects change and syncs
5. New pods are deployed in banking-core namespace
6. Mike views logs in CloudWatch
```

**Test Steps**:
```bash
# Step 1: Login as mike.dev via SSO

# Step 2: Push image to ECR (should succeed)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
docker tag banking-core:v2 ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/banking-core:v2
docker push ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/banking-core:v2

# Step 3: Update GitOps repo (via git)
cd imladris-gitops
# Modify tenants/banking-core/deployment.yaml image tag
git commit -am "Update banking-core to v2"
git push

# Step 4: Verify ArgoCD sync (via ArgoCD UI or CLI)
argocd app get banking-core
argocd app sync banking-core

# Step 5: Verify deployment
kubectl get pods -n banking-core

# Step 6: View logs (should succeed)
aws logs describe-log-streams \
  --log-group-name /aws/eks/imladris-dev-cluster/banking-core
```

### 5.2 Incident Response Flow

**Scenario**: Security group violation triggers auto-remediation

```
1. Jamie (Junior DevOps) monitors CloudWatch for violations
2. Config rule detects SSH port exposed
3. EventBridge triggers SSM automation
4. Security group is auto-remediated
5. Alert sent to team
```

**Test Steps**:
```bash
# Step 1: Intentionally create violation (as admin)
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxx \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Step 2: Wait for Config evaluation (up to 15 minutes)
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name imladris-dev-restricted-ssh

# Step 3: Verify EventBridge triggered automation
aws ssm list-commands --filters Key=DocumentName,Values=imladris-dev-remediate-ssh

# Step 4: Verify remediation occurred
aws ec2 describe-security-groups --group-ids sg-xxx \
  --query 'SecurityGroups[].IpPermissions'
# Expected: SSH rule removed
```

---

## Test Results Template

| Test ID | Test Description | Executed By | Date | Result | Notes |
|---------|-----------------|-------------|------|--------|-------|
| FIN-01 | View Cost Explorer | | | ⬜ PASS / ⬜ FAIL | |
| SDEV-N01 | Cannot create IAM user | | | ⬜ PASS / ⬜ FAIL | |
| ... | ... | | | | |

---

## Rollback Procedures

If critical tests fail:

### IAM Policy Rollback
```hcl
# Revert to broader permissions temporarily
"iam:*"  # Instead of "iam:Get*", "iam:List*"
```

### Security Group Rollback
```hcl
# Allow broader port range if services break
ingress {
  from_port   = 0
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]
}
```

---

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Platform Lead | | | |
| Security Lead | | | |
| DevOps Lead | | | |

---

## Appendix: Quick Reference Commands

```bash
# Get SSO start URL
terraform output sso_start_url

# Bootstrap cluster
aws codebuild start-build --project-name imladris-eks-bootstrap --region us-east-1

# Check CodeBuild logs
aws logs tail /aws/codebuild/imladris-eks-bootstrap --follow

# Validate Terraform
terraform validate && terraform plan
```
