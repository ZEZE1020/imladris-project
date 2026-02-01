# Governance Module - Policy Enforcement & Auto-Remediation
# The "Self-Healing" Infrastructure Component

# AWS Config Configuration Recorder
resource "aws_config_configuration_recorder_status" "recorder" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "imladris-${var.environment}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_iam_role_policy_attachment.config_role_policy]
}

# S3 Bucket for Config
resource "aws_s3_bucket" "config" {
  bucket        = "imladris-${var.environment}-config-${random_string.suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = aws_s3_bucket.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config.arn
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Config Delivery Channel
resource "aws_config_delivery_channel" "main" {
  name           = "imladris-${var.environment}-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config.id

  depends_on = [
    aws_s3_bucket_policy.config_bucket_policy,
    aws_iam_role.config_role,
    aws_config_configuration_recorder.recorder
  ]
}

# AWS Config Rule - Restricted SSH
resource "aws_config_config_rule" "restricted_ssh" {
  name = "imladris-${var.environment}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

# AWS Config Rule - No Public Read Access
resource "aws_config_config_rule" "no_public_read" {
  name = "imladris-${var.environment}-no-public-read-access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

# EventBridge Rule for Config Compliance Violations
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name        = "imladris-${var.environment}-config-compliance"
  description = "Capture Config compliance violations"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

# EventBridge Target - SSM Automation
resource "aws_cloudwatch_event_target" "ssm_automation" {
  rule      = aws_cloudwatch_event_rule.config_compliance.name
  target_id = "TriggerSSMAutomation"
  arn       = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:automation-definition/imladris-${var.environment}-remediate-ssh"

  role_arn = aws_iam_role.eventbridge_role.arn

  input_transformer {
    input_paths = {
      configRuleName = "$.detail.configRuleName"
      resourceId     = "$.detail.resourceId"
      resourceType   = "$.detail.resourceType"
    }
    input_template = jsonencode({
      configRuleName = "<configRuleName>"
      resourceId     = "<resourceId>"
      resourceType   = "<resourceType>"
    })
  }
}

# SSM Automation Document for SSH Remediation
resource "aws_ssm_document" "remediate_ssh" {
  name          = "imladris-${var.environment}-remediate-ssh"
  document_type = "Automation"
  document_format = "YAML"

  content = file("${path.module}/automation/remediate-ssh.yaml")
}

# IAM Role for Config
resource "aws_iam_role" "config_role" {
  name = "imladris-${var.environment}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# IAM Role for EventBridge
resource "aws_iam_role" "eventbridge_role" {
  name = "imladris-${var.environment}-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_ssm_policy" {
  name = "imladris-${var.environment}-eventbridge-ssm-policy"
  role = aws_iam_role.eventbridge_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:StartAutomationExecution"
        ]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:automation-definition/imladris-${var.environment}-remediate-ssh"
        ]
      }
    ]
  })
}

# Random string for unique bucket naming
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Data sources
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}