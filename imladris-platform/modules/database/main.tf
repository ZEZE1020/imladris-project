# Database Module - Aurora Serverless v2 (PostgreSQL)
# Zero Trust: IAM auth, private subnets only, KMS encryption, no public access

# ===== SUBNET GROUP =====
resource "aws_db_subnet_group" "aurora" {
  name       = "imladris-${var.environment}-aurora"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "imladris-${var.environment}-aurora-subnet-group"
  }
}

# ===== SECURITY GROUP =====
resource "aws_security_group" "aurora" {
  name_prefix = "imladris-${var.environment}-aurora-"
  description = "Security group for Aurora Serverless v2 cluster"
  vpc_id      = var.vpc_id

  # PostgreSQL from VPC only
  ingress {
    description = "PostgreSQL from VPC CIDR"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # No egress needed — Aurora is a managed service
  egress {
    description = "Allow responses back to VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "imladris-${var.environment}-aurora-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ===== KMS KEY =====
resource "aws_kms_key" "aurora" {
  description             = "KMS key for Aurora cluster encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true # Trivy: AVD-AWS-0065

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
        Sid    = "Allow RDS Service"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
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
      }
    ]
  })

  tags = {
    Name = "imladris-${var.environment}-aurora-key"
  }
}

resource "aws_kms_alias" "aurora" {
  name          = "alias/imladris-${var.environment}-aurora"
  target_key_id = aws_kms_key.aurora.key_id
}

# ===== AURORA CLUSTER =====
resource "aws_rds_cluster" "main" {
  cluster_identifier = "imladris-${var.environment}-aurora"
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned" # Required for Serverless v2
  engine_version     = var.engine_version
  database_name      = var.database_name

  # IAM Authentication — Zero Trust, no passwords in app code
  iam_database_authentication_enabled = true

  # Master credentials stored in Secrets Manager (rotated automatically)
  manage_master_user_password   = true
  master_username               = var.master_username
  master_user_secret_kms_key_id = aws_kms_key.aurora.key_id

  # Networking — private subnets only, no public access
  db_subnet_group_name   = aws_db_subnet_group.aurora.name
  vpc_security_group_ids = [aws_security_group.aurora.id]

  # Encryption at rest
  storage_encrypted = true # Trivy: AVD-AWS-0079
  kms_key_id        = aws_kms_key.aurora.arn

  # Serverless v2 scaling
  serverlessv2_scaling_configuration {
    min_capacity = var.min_capacity
    max_capacity = var.max_capacity
  }

  # Backup and recovery
  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = "03:00-04:00"
  preferred_maintenance_window = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot        = true
  deletion_protection          = var.deletion_protection
  skip_final_snapshot          = var.environment != "prod"
  final_snapshot_identifier    = var.environment == "prod" ? "imladris-${var.environment}-aurora-final" : null

  # Enhanced monitoring and logging
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = {
    Name        = "imladris-${var.environment}-aurora"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ===== AURORA INSTANCES (Serverless v2) =====
resource "aws_rds_cluster_instance" "writer" {
  identifier          = "imladris-${var.environment}-aurora-writer"
  cluster_identifier  = aws_rds_cluster.main.id
  instance_class      = "db.serverless"
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  publicly_accessible = false # Zero Trust: never public

  # Enhanced monitoring
  monitoring_interval          = 30
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.aurora.arn

  tags = {
    Name = "imladris-${var.environment}-aurora-writer"
  }
}

resource "aws_rds_cluster_instance" "reader" {
  count = var.reader_count

  identifier          = "imladris-${var.environment}-aurora-reader-${count.index + 1}"
  cluster_identifier  = aws_rds_cluster.main.id
  instance_class      = "db.serverless"
  engine              = aws_rds_cluster.main.engine
  engine_version      = aws_rds_cluster.main.engine_version
  publicly_accessible = false

  monitoring_interval          = 30
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.aurora.arn

  tags = {
    Name = "imladris-${var.environment}-aurora-reader-${count.index + 1}"
  }
}

# ===== IAM ROLE FOR POD-LEVEL DATABASE ACCESS =====
# EKS pods assume this role via IRSA to get IAM auth tokens
resource "aws_iam_role" "db_access" {
  name = "imladris-${var.environment}-db-access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.eks_oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${var.eks_oidc_provider_url}:sub" = "system:serviceaccount:${var.app_namespace}:${var.app_service_account}"
            "${var.eks_oidc_provider_url}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name = "imladris-${var.environment}-db-access-role"
  }
}

resource "aws_iam_role_policy" "db_access" {
  name = "imladris-${var.environment}-db-iam-auth"
  role = aws_iam_role.db_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "rds-db:connect"
        Resource = "arn:aws:rds-db:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_rds_cluster.main.cluster_resource_id}/${var.app_db_username}"
      }
    ]
  })
}

# ===== ENHANCED MONITORING IAM ROLE =====
resource "aws_iam_role" "rds_monitoring" {
  name = "imladris-${var.environment}-rds-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ===== CLOUDWATCH ALARMS =====
resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "imladris-${var.environment}-aurora-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Aurora CPU utilization above 80% for 15 minutes"

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier
  }

  tags = {
    Name = "imladris-${var.environment}-aurora-cpu-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "freeable_memory" {
  alarm_name          = "imladris-${var.environment}-aurora-memory-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 3
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 256000000 # 256 MB
  alarm_description   = "Aurora freeable memory below 256MB for 15 minutes"

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.main.cluster_identifier
  }

  tags = {
    Name = "imladris-${var.environment}-aurora-memory-alarm"
  }
}

# ===== DATA SOURCES =====
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
