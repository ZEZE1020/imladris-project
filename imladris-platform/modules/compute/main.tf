# Compute Module - EKS Fargate Cluster
# Zero Trust Compute: No EC2 nodes, Fargate only

# EKS Cluster
resource "aws_eks_cluster" "main" {
  name     = "imladris-${var.environment}-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false  # Zero Trust: No public API access
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_service_policy,
    aws_cloudwatch_log_group.eks_cluster
  ]
}

# CloudWatch Log Group for EKS
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/imladris-${var.environment}-cluster/cluster"
  retention_in_days = 30
}

# KMS Key for EKS Encryption
resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key for imladris-${var.environment}"
  deletion_window_in_days = 7

  tags = {
    Name = "imladris-${var.environment}-eks-key"
  }
}

resource "aws_kms_alias" "eks" {
  name          = "alias/imladris-${var.environment}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# EKS Fargate Profile
resource "aws_eks_fargate_profile" "main" {
  cluster_name           = aws_eks_cluster.main.name
  fargate_profile_name   = "imladris-${var.environment}-fargate-profile"
  pod_execution_role_arn = aws_iam_role.fargate_pod_execution_role.arn
  subnet_ids             = var.private_subnet_ids

  selector {
    namespace = "default"
  }

  selector {
    namespace = "banking-core"
  }

  selector {
    namespace = "kube-system"
  }

  selector {
    namespace = "banking-ui"
  }

  selector {
    namespace = "argocd"
  }

  depends_on = [
    aws_iam_role_policy_attachment.fargate_pod_execution_role_policy
  ]
}

# Security Group for EKS Cluster
resource "aws_security_group" "eks_cluster" {
  name_prefix = "imladris-${var.environment}-eks-cluster-"
  vpc_id      = var.vpc_id

  # Allow all traffic within VPC - controlled by VPC Lattice
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]  # VPC CIDR only - Zero Trust
  }

  tags = {
    Name = "imladris-${var.environment}-eks-cluster-sg"
  }
}

# IAM Role for EKS Cluster
resource "aws_iam_role" "eks_cluster_role" {
  name = "imladris-${var.environment}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "eks_service_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# IAM Role for Fargate Pod Execution
resource "aws_iam_role" "fargate_pod_execution_role" {
  name = "imladris-${var.environment}-fargate-pod-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks-fargate-pods.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "fargate_pod_execution_role_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
  role       = aws_iam_role.fargate_pod_execution_role.name
}

# IAM Identity Center Permission Set for Platform Engineers (optional)
resource "aws_ssoadmin_permission_set" "platform_engineers" {
  count = var.identity_center_instance_arn != "" ? 1 : 0

  instance_arn     = var.identity_center_instance_arn
  name             = "ImladrisPlatformEngineers"
  description      = "Platform engineers access to Imladris EKS cluster"
  session_duration = "PT8H"
}

resource "aws_ssoadmin_managed_policy_attachment" "platform_engineers_eks" {
  count = var.identity_center_instance_arn != "" ? 1 : 0

  instance_arn       = var.identity_center_instance_arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  permission_set_arn = aws_ssoadmin_permission_set.platform_engineers[0].arn
}

# EKS Access Entry for Identity Center Users (optional)
resource "aws_eks_access_entry" "platform_engineers" {
  count = var.identity_center_instance_arn != "" ? 1 : 0

  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_ssoadmin_permission_set.platform_engineers[0].arn
  kubernetes_groups = ["system:masters"]
  type             = "STANDARD"
}

# VPC Lattice Service for EKS API
resource "aws_vpclattice_service" "eks_api" {
  name               = "imladris-${var.environment}-eks-api"
  auth_type          = "AWS_IAM"
  custom_domain_name = "eks-api.imladris.${var.environment}.local"

  tags = {
    Name = "imladris-${var.environment}-eks-api-service"
  }
}

resource "aws_vpclattice_service_network_service_association" "eks_api" {
  service_identifier         = aws_vpclattice_service.eks_api.id
  service_network_identifier = var.vpc_lattice_service_network_id

  tags = {
    Name = "imladris-${var.environment}-eks-api-association"
  }
}