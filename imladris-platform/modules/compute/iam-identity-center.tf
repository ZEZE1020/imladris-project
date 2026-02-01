# IAM Identity Center - Users and Permission Sets
# Zero Trust Banking Platform RBAC

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# IAM Identity Center Instance (must be created manually first)
data "aws_ssoadmin_instances" "main" {}

locals {
  identity_center_instance_arn = tolist(data.aws_ssoadmin_instances.main.arns)[0]
  identity_center_store_id     = tolist(data.aws_ssoadmin_instances.main.identity_store_ids)[0]
}

# ===== USERS =====

# 1. Financial Analyst (FinOps)
resource "aws_identitystore_user" "finops_analyst" {
  identity_store_id = local.identity_center_store_id
  
  display_name = "Sarah Johnson"
  user_name    = "sarah.finops"
  
  name {
    given_name  = "Sarah"
    family_name = "Johnson"
  }
  
  emails {
    value   = "sarah.finops@imladris.bank"
    primary = true
  }
}

# 2. Senior DevOps Engineer
resource "aws_identitystore_user" "senior_devops" {
  identity_store_id = local.identity_center_store_id
  
  display_name = "Alex Rodriguez"
  user_name    = "alex.devops"
  
  name {
    given_name  = "Alex"
    family_name = "Rodriguez"
  }
  
  emails {
    value   = "alex.devops@imladris.bank"
    primary = true
  }
}

# 3. Junior DevOps Engineer
resource "aws_identitystore_user" "junior_devops" {
  identity_store_id = local.identity_center_store_id
  
  display_name = "Jamie Chen"
  user_name    = "jamie.devops"
  
  name {
    given_name  = "Jamie"
    family_name = "Chen"
  }
  
  emails {
    value   = "jamie.devops@imladris.bank"
    primary = true
  }
}

# 4. Backend Developer
resource "aws_identitystore_user" "backend_developer" {
  identity_store_id = local.identity_center_store_id
  
  display_name = "Mike Thompson"
  user_name    = "mike.dev"
  
  name {
    given_name  = "Mike"
    family_name = "Thompson"
  }
  
  emails {
    value   = "mike.dev@imladris.bank"
    primary = true
  }
}

# 5. Frontend Developer
resource "aws_identitystore_user" "frontend_developer" {
  identity_store_id = local.identity_center_store_id
  
  display_name = "Lisa Wang"
  user_name    = "lisa.dev"
  
  name {
    given_name  = "Lisa"
    family_name = "Wang"
  }
  
  emails {
    value   = "lisa.dev@imladris.bank"
    primary = true
  }
}

# ===== PERMISSION SETS =====

# 1. FinOps Analyst Permission Set
resource "aws_ssoadmin_permission_set" "finops_analyst" {
  instance_arn     = local.identity_center_instance_arn
  name             = "ImladrisFinOpsAnalyst"
  description      = "Financial operations and cost management"
  session_duration = "PT4H"
  
  tags = {
    Role = "FinOps"
    Team = "Finance"
  }
}

# FinOps Policy - Cost Management and Read-Only Access
resource "aws_ssoadmin_permission_set_inline_policy" "finops_policy" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.finops_analyst.arn
  
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # Cost and Billing
          "ce:*",
          "cur:*",
          "budgets:*",
          "pricing:*",
          "support:*",
          
          # Read-only access to resources
          "ec2:Describe*",
          "eks:Describe*",
          "eks:List*",
          "iam:Get*",
          "iam:List*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "cloudwatch:Describe*",
          "logs:Describe*",
          "logs:Get*",
          
          # Tagging for cost allocation
          "tag:GetResources",
          "tag:GetTagKeys",
          "tag:GetTagValues",
          "resource-groups:*"
        ]
        Resource = "*"
      },
      {
        Effect = "Deny"
        Action = [
          "iam:Create*",
          "iam:Delete*",
          "iam:Put*",
          "iam:Update*",
          "iam:Attach*",
          "iam:Detach*"
        ]
        Resource = "*"
      }
    ]
  })
}

# 2. Senior DevOps Permission Set
resource "aws_ssoadmin_permission_set" "senior_devops" {
  instance_arn     = local.identity_center_instance_arn
  name             = "ImladrisSeniorDevOps"
  description      = "Full platform management and infrastructure deployment"
  session_duration = "PT8H"
  
  tags = {
    Role = "DevOps"
    Level = "Senior"
  }
}

# Senior DevOps Policy - Full Infrastructure Access
resource "aws_ssoadmin_permission_set_inline_policy" "senior_devops_policy" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.senior_devops.arn
  
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EKS Full Access
          "eks:*",
          
          # VPC and Networking
          "ec2:*",
          "vpc-lattice:*",
          
          # IAM for service roles
          "iam:*",
          
          # Config and Compliance
          "config:*",
          "events:*",
          "ssm:*",
          
          # Monitoring
          "cloudwatch:*",
          "logs:*",
          
          # Container Registry
          "ecr:*",
          
          # KMS
          "kms:*",
          
          # S3 for Terraform state
          "s3:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# 3. Junior DevOps Permission Set
resource "aws_ssoadmin_permission_set" "junior_devops" {
  instance_arn     = local.identity_center_instance_arn
  name             = "ImladrisJuniorDevOps"
  description      = "Monitoring and limited infrastructure access"
  session_duration = "PT6H"
  
  tags = {
    Role = "DevOps"
    Level = "Junior"
  }
}

# Junior DevOps Policy - Read-Only + Monitoring
resource "aws_ssoadmin_permission_set_inline_policy" "junior_devops_policy" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.junior_devops.arn
  
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EKS Read and Limited Write
          "eks:Describe*",
          "eks:List*",
          "eks:AccessKubernetesApi",
          
          # Monitoring and Logs
          "cloudwatch:*",
          "logs:*",
          
          # Read-only infrastructure
          "ec2:Describe*",
          "vpc-lattice:Get*",
          "vpc-lattice:List*",
          
          # Config monitoring
          "config:Get*",
          "config:List*",
          "config:Describe*",
          
          # ECR read-only
          "ecr:Get*",
          "ecr:List*",
          "ecr:Describe*"
        ]
        Resource = "*"
      }
    ]
  })
}

# 4. Backend Developer Permission Set
resource "aws_ssoadmin_permission_set" "backend_developer" {
  instance_arn     = local.identity_center_instance_arn
  name             = "ImladrisBackendDeveloper"
  description      = "Banking service development and deployment"
  session_duration = "PT8H"
  
  tags = {
    Role = "Developer"
    Team = "Backend"
  }
}

# Backend Developer Policy - Application Deployment
resource "aws_ssoadmin_permission_set_inline_policy" "backend_developer_policy" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.backend_developer.arn
  
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EKS API access for banking-core namespace
          "eks:AccessKubernetesApi"
        ]
        Resource = "arn:aws:eks:*:*:cluster/imladris-*"
      },
      {
        Effect = "Allow"
        Action = [
          # ECR for banking services
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = [
          "arn:aws:ecr:*:*:repository/banking-*",
          "arn:aws:ecr:*:*:repository/imladris-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # CloudWatch Logs for applications
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLog*"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/eks/imladris-*/banking-core/*"
      }
    ]
  })
}

# 5. Frontend Developer Permission Set
resource "aws_ssoadmin_permission_set" "frontend_developer" {
  instance_arn     = local.identity_center_instance_arn
  name             = "ImladrisFrontendDeveloper"
  description      = "Frontend development and UI services"
  session_duration = "PT8H"
  
  tags = {
    Role = "Developer"
    Team = "Frontend"
  }
}

# Frontend Developer Policy - UI Application Deployment
resource "aws_ssoadmin_permission_set_inline_policy" "frontend_developer_policy" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.frontend_developer.arn
  
  inline_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EKS API access for banking-ui namespace
          "eks:AccessKubernetesApi"
        ]
        Resource = "arn:aws:eks:*:*:cluster/imladris-*"
      },
      {
        Effect = "Allow"
        Action = [
          # ECR for UI services
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = [
          "arn:aws:ecr:*:*:repository/banking-ui-*",
          "arn:aws:ecr:*:*:repository/imladris-ui-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # CloudWatch Logs for UI applications
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLog*"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/eks/imladris-*/banking-ui/*"
      }
    ]
  })
}

# ===== ACCOUNT ASSIGNMENTS =====

# Get AWS account ID
data "aws_caller_identity" "current" {}

# Assign FinOps Analyst
resource "aws_ssoadmin_account_assignment" "finops_assignment" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.finops_analyst.arn
  
  principal_id   = aws_identitystore_user.finops_analyst.user_id
  principal_type = "USER"
  
  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# Assign Senior DevOps
resource "aws_ssoadmin_account_assignment" "senior_devops_assignment" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.senior_devops.arn
  
  principal_id   = aws_identitystore_user.senior_devops.user_id
  principal_type = "USER"
  
  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# Assign Junior DevOps
resource "aws_ssoadmin_account_assignment" "junior_devops_assignment" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.junior_devops.arn
  
  principal_id   = aws_identitystore_user.junior_devops.user_id
  principal_type = "USER"
  
  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# Assign Backend Developer
resource "aws_ssoadmin_account_assignment" "backend_developer_assignment" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.backend_developer.arn
  
  principal_id   = aws_identitystore_user.backend_developer.user_id
  principal_type = "USER"
  
  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# Assign Frontend Developer
resource "aws_ssoadmin_account_assignment" "frontend_developer_assignment" {
  instance_arn       = local.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.frontend_developer.arn
  
  principal_id   = aws_identitystore_user.frontend_developer.user_id
  principal_type = "USER"
  
  target_id   = data.aws_caller_identity.current.account_id
  target_type = "AWS_ACCOUNT"
}

# ===== OUTPUTS =====

output "identity_center_instance_arn" {
  description = "IAM Identity Center instance ARN"
  value       = local.identity_center_instance_arn
}

output "users" {
  description = "Created users and their roles"
  value = {
    finops_analyst      = aws_identitystore_user.finops_analyst.user_name
    senior_devops       = aws_identitystore_user.senior_devops.user_name
    junior_devops       = aws_identitystore_user.junior_devops.user_name
    backend_developer   = aws_identitystore_user.backend_developer.user_name
    frontend_developer  = aws_identitystore_user.frontend_developer.user_name
  }
}

output "sso_start_url" {
  description = "AWS SSO start URL"
  value       = "https://${split("/", local.identity_center_instance_arn)[1]}.awsapps.com/start"
}