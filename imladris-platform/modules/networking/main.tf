# Networking Module - Zero Trust VPC with VPC Lattice
# No public subnets, no internet gateways - pure private networking

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "imladris-${var.environment}-vpc"
  }
}

# Private Subnets Only
resource "aws_subnet" "private" {
  count = length(var.availability_zones)

  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "imladris-${var.environment}-private-${count.index + 1}"
    Type = "Private"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/cluster/imladris-${var.environment}-cluster" = "owned"
  }
}

# VPC Endpoints for AWS Services (no internet access needed)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "imladris-${var.environment}-s3-endpoint"
  }
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "imladris-${var.environment}-ecr-dkr-endpoint"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "imladris-${var.environment}-ecr-api-endpoint"
  }
}

resource "aws_vpc_endpoint" "eks" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.eks"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "imladris-${var.environment}-eks-endpoint"
  }
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "imladris-${var.environment}-vpc-endpoints-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "imladris-${var.environment}-vpc-endpoints-sg"
  }
}

# Route Table for Private Subnets
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "imladris-${var.environment}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# VPC Lattice Service Network - The Heart of Zero Trust
resource "aws_vpclattice_service_network" "main" {
  name      = "imladris-${var.environment}-lattice"
  auth_type = "AWS_IAM"

  tags = {
    Name = "imladris-${var.environment}-lattice-network"
  }
}

# Associate VPC with Lattice Service Network
resource "aws_vpclattice_service_network_vpc_association" "main" {
  vpc_identifier             = aws_vpc.main.id
  service_network_identifier = aws_vpclattice_service_network.main.id

  tags = {
    Name = "imladris-${var.environment}-lattice-vpc-association"
  }
}

# Data sources
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}