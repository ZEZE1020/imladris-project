# Secure Registry Module - Harbor Pull-Through Cache
# Supply Chain Security Implementation

# Data source to get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# KMS key for EBS encryption (simulating vault storage)
resource "aws_kms_key" "registry_storage" {
  description             = "KMS key for Harbor registry encrypted storage"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EC2 Service"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.harbor_instance.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-harbor-storage-key"
    Environment = var.environment
    Purpose     = "SecureRegistry"
  }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_alias" "registry_storage" {
  name          = "alias/${var.environment}-harbor-storage"
  target_key_id = aws_kms_key.registry_storage.key_id
}

# IAM role for the Harbor EC2 instance
resource "aws_iam_role" "harbor_instance" {
  name = "${var.environment}-harbor-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-harbor-instance-role"
    Environment = var.environment
  }
}

# IAM instance profile for Harbor instance
resource "aws_iam_instance_profile" "harbor_instance" {
  name = "${var.environment}-harbor-instance-profile"
  role = aws_iam_role.harbor_instance.name
}

# IAM policy for Harbor to access ECR and CloudWatch
resource "aws_iam_policy" "harbor_permissions" {
  name        = "${var.environment}-harbor-permissions"
  description = "Permissions for Harbor registry instance"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowECRAuth"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowECRPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "arn:aws:ecr:*:${data.aws_caller_identity.current.account_id}:repository/*"
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/harbor/${var.environment}/*"
      },
      {
        Sid    = "AllowSSMParameters"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/${var.environment}/harbor/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "harbor_permissions" {
  policy_arn = aws_iam_policy.harbor_permissions.arn
  role       = aws_iam_role.harbor_instance.name
}

# Harbor EC2 instance in private subnet
resource "aws_instance" "harbor_registry" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.harbor_registry.id]
  iam_instance_profile   = aws_iam_instance_profile.harbor_instance.name
  monitoring             = true
  ebs_optimized          = true

  # Require IMDSv2 for enhanced security (prevents SSRF attacks)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # Enforces IMDSv2
    http_put_response_hop_limit = 1
  }

  # Encrypted root volume
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
    kms_key_id  = aws_kms_key.registry_storage.arn

    tags = {
      Name        = "${var.environment}-harbor-root-volume"
      Environment = var.environment
    }
  }

  # Encrypted EBS volume for Harbor data (simulating vault storage)
  ebs_block_device {
    device_name = "/dev/xvdb"
    volume_type = "gp3"
    volume_size = var.storage_size_gb
    encrypted   = true
    kms_key_id  = aws_kms_key.registry_storage.arn

    tags = {
      Name        = "${var.environment}-harbor-data-volume"
      Environment = var.environment
      Purpose     = "RegistryStorage"
    }
  }

  user_data = base64encode(file("${path.module}/harbor-setup.sh"))

  tags = {
    Name         = "${var.environment}-harbor-registry"
    Environment  = var.environment
    Purpose      = "SecureRegistry"
    Component    = "SupplyChainSecurity"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

# Elastic IP for Harbor instance (for consistent access from CI/CD)
resource "aws_eip" "harbor_registry" {
  instance = aws_instance.harbor_registry.id
  domain   = "vpc"

  tags = {
    Name        = "${var.environment}-harbor-eip"
    Environment = var.environment
  }

  depends_on = [aws_instance.harbor_registry]
}

# CloudWatch Log Group for Harbor logs
resource "aws_cloudwatch_log_group" "harbor_logs" {
  name              = "/aws/ec2/harbor/${var.environment}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.registry_storage.arn

  tags = {
    Name        = "${var.environment}-harbor-logs"
    Environment = var.environment
  }
}