# Secure Registry Network Security
# This Security Group allows the Build Server to pull base images, but blocks direct internet access for the Build Server itself.

# Security group for Harbor registry
resource "aws_security_group" "harbor_registry" {
  name_prefix = "${var.environment}-harbor-registry-"
  vpc_id      = var.vpc_id

  description = "Security group for Harbor registry with restricted CI/CD access"

  # HTTPS access from CI/CD build environments
  ingress {
    description = "HTTPS from CI/CD build environments"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [for subnet in data.aws_subnet.cicd_subnets : subnet.cidr_block]
  }

  # HTTP access from CI/CD build environments (for health checks)
  ingress {
    description = "HTTP from CI/CD build environments"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [for subnet in data.aws_subnet.cicd_subnets : subnet.cidr_block]
  }

  # HTTPS access from build environment subnets
  dynamic "ingress" {
    for_each = length(var.build_subnet_ids) > 0 ? [1] : []
    content {
      description = "HTTPS from build environments"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [for subnet in data.aws_subnet.build_subnets : subnet.cidr_block]
    }
  }

  # SSH access for emergency administration (restricted to specific CIDR blocks)
  dynamic "ingress" {
    for_each = length(var.allowed_cidr_blocks) > 0 ? [1] : []
    content {
      description = "SSH for emergency administration"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidr_blocks
    }
  }

  # Outbound rules for Harbor functionality
  egress {
    description = "HTTPS to Docker Hub for image pulls"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP to Docker Hub for image pulls"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "NTP for time synchronization"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS for AWS services (ECR, S3, etc.)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-harbor-registry-sg"
    Environment = var.environment
    Purpose     = "SecureRegistryAccess"
  }
}

# Data sources for subnet information
data "aws_subnet" "cicd_subnets" {
  count = length(var.cicd_subnet_ids)
  id    = var.cicd_subnet_ids[count.index]
}

data "aws_subnet" "build_subnets" {
  count = length(var.build_subnet_ids)
  id    = var.build_subnet_ids[count.index]
}

# Network ACL for additional layer of security
resource "aws_network_acl" "harbor_registry" {
  vpc_id     = var.vpc_id
  subnet_ids = [var.private_subnet_ids[0]]

  # Allow HTTPS inbound from CI/CD subnets
  dynamic "ingress" {
    for_each = data.aws_subnet.cicd_subnets
    content {
      rule_no    = 100 + ingress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value.cidr_block
      from_port  = 443
      to_port    = 443
    }
  }

  # Allow HTTP inbound from CI/CD subnets (health checks)
  dynamic "ingress" {
    for_each = data.aws_subnet.cicd_subnets
    content {
      rule_no    = 200 + ingress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value.cidr_block
      from_port  = 80
      to_port    = 80
    }
  }

  # Allow return traffic
  ingress {
    rule_no    = 900
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow all outbound traffic
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name        = "${var.environment}-harbor-registry-nacl"
    Environment = var.environment
    Purpose     = "SecureRegistryNetworkAccess"
  }
}

# VPC Endpoint for ECR to avoid internet traffic for AWS ECR access
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [var.private_subnet_ids[0]]
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
  private_dns_enabled = true

  tags = {
    Name        = "${var.environment}-ecr-api-endpoint"
    Environment = var.environment
    Purpose     = "SecureECRAccess"
  }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [var.private_subnet_ids[0]]
  security_group_ids  = [aws_security_group.vpc_endpoint.id]
  private_dns_enabled = true

  tags = {
    Name        = "${var.environment}-ecr-dkr-endpoint"
    Environment = var.environment
    Purpose     = "SecureECRAccess"
  }
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoint" {
  name_prefix = "${var.environment}-vpc-endpoint-"
  vpc_id      = var.vpc_id

  description = "Security group for VPC endpoints used by Harbor"

  ingress {
    description     = "HTTPS from Harbor instance"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.harbor_registry.id]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-vpc-endpoint-sg"
    Environment = var.environment
    Purpose     = "VPCEndpointAccess"
  }
}

# Data source for current AWS region
data "aws_region" "current" {}