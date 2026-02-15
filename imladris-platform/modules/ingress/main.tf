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

  enable_deletion_protection = var.enable_deletion_protection

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
      sse_algorithm = "aws:kms"
    }
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
