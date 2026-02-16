# Ingress Module - Zero Trust External Access via AWS PrivateLink
# No Internet Gateway. Partners/clients connect through PrivateLink endpoints.
#
# This module demonstrates the "no IGW" alternative for accepting inbound traffic:
#   Partner VPC → PrivateLink Endpoint → NLB → VPC Lattice → EKS Service
#
# Why PrivateLink instead of IGW?
#   - Traffic never traverses the public internet
#   - Consumer must be explicitly granted access
#   - Producers control which services are exposed
#   - Fine-grained IAM + security group control

# ─── Network Load Balancer (PrivateLink requires NLB) ───────────────────────

resource "aws_lb" "private_ingress" {
  name               = "imladris-${var.environment}-ingress"
  internal           = true  # Zero Trust: internal only
  load_balancer_type = "network"
  subnets            = var.private_subnet_ids

  enable_deletion_protection    = var.enable_deletion_protection
  enable_cross_zone_load_balancing = true

  dynamic "access_logs" {
    for_each = var.enable_access_logging ? [1] : []
    content {
      bucket  = aws_s3_bucket.nlb_access_logs[0].id
      prefix  = "nlb-logs"
      enabled = true
    }
  }

  tags = {
    Name        = "imladris-${var.environment}-private-ingress"
    Purpose     = "PrivateLink-ingress"
    Environment = var.environment
  }
}

# ─── NLB Target Group → forwards to VPC Lattice or EKS services ─────────────

resource "aws_lb_target_group" "banking_api" {
  name        = "imladris-${var.environment}-banking-api"
  port        = 443
  protocol    = "TLS"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 30
  }

  tags = {
    Name        = "imladris-${var.environment}-banking-api-tg"
    Environment = var.environment
  }
}

# ─── NLB Listener (TLS termination) ─────────────────────────────────────────

resource "aws_lb_listener" "tls" {
  load_balancer_arn = aws_lb.private_ingress.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.banking_api.arn
  }

  tags = {
    Name = "imladris-${var.environment}-tls-listener"
  }
}

# ─── VPC Endpoint Service (PrivateLink Producer) ────────────────────────────
# This is what partner VPCs connect to. No internet required.

resource "aws_vpc_endpoint_service" "banking_api" {
  acceptance_required        = var.require_manual_acceptance
  network_load_balancer_arns = [aws_lb.private_ingress.arn]

  # Restrict which AWS accounts can create endpoints to this service
  allowed_principals = var.allowed_principal_arns

  tags = {
    Name        = "imladris-${var.environment}-banking-api-endpoint-svc"
    Environment = var.environment
    ZeroTrust   = "true"
  }
}

# ─── Security Group for NLB targets ─────────────────────────────────────────

resource "aws_security_group" "ingress_targets" {
  name_prefix = "imladris-${var.environment}-ingress-targets-"
  description = "Security group for PrivateLink ingress NLB targets"
  vpc_id      = var.vpc_id

  # Allow inbound from NLB (via VPC CIDR — NLB preserves source IP in TCP mode)
  ingress {
    description = "TLS from NLB / partner PrivateLink endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Zero Trust egress: only to VPC
  egress {
    description = "Responses within VPC only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name        = "imladris-${var.environment}-ingress-targets-sg"
    Environment = var.environment
  }
}

# ─── CloudWatch Alarms for PrivateLink health ───────────────────────────────

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  alarm_name          = "imladris-${var.environment}-ingress-unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "PrivateLink ingress has unhealthy targets"

  dimensions = {
    TargetGroup  = aws_lb_target_group.banking_api.arn_suffix
    LoadBalancer = aws_lb.private_ingress.arn_suffix
  }

  tags = {
    Name        = "imladris-${var.environment}-ingress-health-alarm"
    Environment = var.environment
  }
}

# ─── Access Logging for NLB (audit trail) ────────────────────────────────────

resource "aws_s3_bucket" "nlb_access_logs" {
  count         = var.enable_access_logging ? 1 : 0
  bucket        = "imladris-${var.environment}-nlb-logs-${random_string.suffix.result}"
  force_destroy = true

  tags = {
    Name        = "imladris-${var.environment}-nlb-access-logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "nlb_access_logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.nlb_access_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "nlb_access_logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.nlb_access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.nlb_logs[0].arn
    }
    bucket_key_enabled = true
  }
}

# KMS CMK for NLB access logs S3 bucket
resource "aws_kms_key" "nlb_logs" {
  count                   = var.enable_access_logging ? 1 : 0
  description             = "CMK for NLB access logs S3 bucket encryption"
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
        Sid    = "Allow ELB Service"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "imladris-${var.environment}-nlb-logs-key"
    Environment = var.environment
  }
}

# S3 Bucket Versioning for NLB access logs
resource "aws_s3_bucket_versioning" "nlb_access_logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.nlb_access_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# Dedicated S3 Bucket for logging of the NLB access logs bucket (to avoid self-logging loop)
resource "aws_s3_bucket" "nlb_access_logs_logs" {
  count = var.enable_access_logging ? 1 : 0

  bucket = "imladris-${var.environment}-nlb-access-logs-logs-${random_string.suffix.result}"

  tags = {
    Name        = "imladris-${var.environment}-nlb-access-logs-logs"
    Environment = var.environment
  }
}

# Block public access for the logs-of-logs bucket
resource "aws_s3_bucket_public_access_block" "nlb_access_logs_logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.nlb_access_logs_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Logging for NLB access logs (logs go to a separate bucket to avoid self-logging loop)
resource "aws_s3_bucket_logging" "nlb_access_logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.nlb_access_logs[0].id

  target_bucket = aws_s3_bucket.nlb_access_logs_logs[0].id
  target_prefix = "nlb-access-logs/"
}

# S3 Bucket Lifecycle Configuration
resource "aws_s3_bucket_lifecycle_configuration" "nlb_access_logs" {
  count  = var.enable_access_logging ? 1 : 0
  bucket = aws_s3_bucket.nlb_access_logs[0].id

  rule {
    id     = "log-retention"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

data "aws_caller_identity" "current" {}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
