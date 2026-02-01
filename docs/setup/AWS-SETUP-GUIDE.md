# AWS Account Setup for Imladris Platform Deployment

## 1. Root User Prerequisites

### Enable Required AWS Services
```bash
# Enable IAM Identity Center
aws organizations enable-aws-service-access --service-principal sso.amazonaws.com

# Enable AWS Config
aws organizations enable-aws-service-access --service-principal config.amazonaws.com

# Enable EventBridge
aws organizations enable-aws-service-access --service-principal events.amazonaws.com
```

### Create IAM Identity Center Instance
```bash
# Create Identity Center instance
aws sso-admin create-instance --name "Imladris-Banking-Platform"

# Get instance ARN (save this for terraform.tfvars)
aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text
```

## 2. Platform Engineer IAM User

### Create IAM User
```bash
# Create platform engineer user
aws iam create-user --user-name imladris-platform-engineer

# Create access key
aws iam create-access-key --user-name imladris-platform-engineer
```

### Platform Engineer Policy (Deployment Permissions)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "eks:*",
        "iam:*",
        "vpc-lattice:*",
        "config:*",
        "events:*",
        "ssm:*",
        "cloudwatch:*",
        "logs:*",
        "ecr:*",
        "kms:*",
        "s3:*",
        "sso:*",
        "sso-admin:*",
        "identitystore:*",
        "lambda:*",
        "sns:*",
        "sts:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Apply Policy
```bash
# Create policy
aws iam create-policy \
  --policy-name ImladrisPlatformEngineerPolicy \
  --policy-document file://platform-engineer-policy.json

# Attach to user
aws iam attach-user-policy \
  --user-name imladris-platform-engineer \
  --policy-arn arn:aws:iam::ACCOUNT-ID:policy/ImladrisPlatformEngineerPolicy
```

## 3. Configure AWS CLI

```bash
# Configure AWS CLI with platform engineer credentials
aws configure --profile imladris-platform
# Enter Access Key ID
# Enter Secret Access Key
# Enter region: us-east-1
# Enter output format: json

# Set as default profile
export AWS_PROFILE=imladris-platform

# Verify access
aws sts get-caller-identity
```

## 4. Pre-deployment Checks

### Verify Permissions
```bash
# Test EKS permissions
aws eks list-clusters

# Test IAM permissions
aws iam list-roles

# Test Identity Center access
aws sso-admin list-instances

# Test VPC permissions
aws ec2 describe-vpcs
```

### Check Service Limits
```bash
# Check VPC limit (need 1)
aws service-quotas get-service-quota \
  --service-code vpc \
  --quota-code L-F678F1CE

# Check EKS cluster limit (need 1)
aws service-quotas get-service-quota \
  --service-code eks \
  --quota-code L-1194D53C
```

## 5. Required terraform.tfvars Configuration

```hcl
# Copy from terraform.tfvars.example
aws_region     = "us-east-1"
environment    = "demo"
vpc_cidr       = "10.0.0.0/16"
eks_version    = "1.28"

availability_zones = [
  "us-east-1a",
  "us-east-1b"
]

# Add your Identity Center instance ARN here
identity_center_instance_arn = "arn:aws:sso:::instance/ssoins-XXXXXXXXXX"
```

## 6. Deployment Commands

```bash
# Navigate to platform directory
cd imladris-platform

# Copy and configure variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your Identity Center ARN

# Initialize and deploy
terraform init
terraform validate
terraform plan
terraform apply
```

## 7. Post-deployment: Create 5 Users

After infrastructure deployment, create the 5 users:

```bash
# Deploy user management
terraform apply -target=aws_identitystore_user.finops_analyst
terraform apply -target=aws_identitystore_user.senior_devops
terraform apply -target=aws_identitystore_user.junior_devops
terraform apply -target=aws_identitystore_user.backend_developer
terraform apply -target=aws_identitystore_user.frontend_developer
```

## 8. Troubleshooting Common Issues

### Permission Denied Errors
```bash
# Check current user
aws sts get-caller-identity

# Verify policy attachment
aws iam list-attached-user-policies --user-name imladris-platform-engineer
```

### Identity Center Not Available
```bash
# Check if Identity Center is enabled
aws sso-admin list-instances

# If empty, create instance
aws sso-admin create-instance --name "Imladris-Banking"
```

### Region Issues
```bash
# Ensure using us-east-1
aws configure set region us-east-1
export AWS_DEFAULT_REGION=us-east-1
```

## 9. Security Best Practices

- Use temporary credentials when possible
- Enable MFA on root account
- Rotate access keys regularly
- Monitor CloudTrail for deployment activities
- Use least privilege principle

## 10. Cost Considerations

Expected monthly costs:
- EKS Cluster: $73
- Fargate: $150-300
- VPC Lattice: $50
- VPC Endpoints: $88
- Monitoring: $100
- **Total: ~$460-610/month**

Set up billing alerts:
```bash
aws budgets create-budget \
  --account-id ACCOUNT-ID \
  --budget file://budget-alert.json
```