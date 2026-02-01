# Lambda Infrastructure for Drift Enforcement Engine
# Creates Lambda function, IAM roles, and supporting resources

# CloudWatch Log Groups for different event types
resource "aws_cloudwatch_log_group" "high_severity_events" {
  name              = var.high_severity_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = merge(var.tags, {
    "EventType" = "high-severity"
  })
}

resource "aws_cloudwatch_log_group" "process_exec_events" {
  name              = var.process_exec_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = merge(var.tags, {
    "EventType" = "process-execution"
  })
}

resource "aws_cloudwatch_log_group" "file_access_events" {
  name              = var.file_access_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = merge(var.tags, {
    "EventType" = "file-access"
  })
}

resource "aws_cloudwatch_log_group" "network_events" {
  name              = var.network_events_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = merge(var.tags, {
    "EventType" = "network-events"
  })
}

resource "aws_cloudwatch_log_group" "security_incidents" {
  name              = "/aws/security/drift-engine/incidents"
  retention_in_days = 90  # Keep incidents longer for compliance
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = merge(var.tags, {
    "EventType" = "security-incidents"
  })
}

# S3 bucket for security log archival
resource "aws_s3_bucket" "security_logs" {
  bucket = "${var.cluster_name}-security-logs-${random_id.bucket_suffix.hex}"

  tags = merge(var.tags, {
    "Purpose" = "security-log-archive"
  })
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.eks_encryption.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "security_logs_lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    transition {
      days          = 365
      storage_class = "DEEP_ARCHIVE"
    }

    expiration {
      days = 2555  # 7 years for compliance
    }
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Store EKS cluster certificate authority data in Secrets Manager
resource "aws_secretsmanager_secret" "eks_ca_data" {
  name        = "${var.cluster_name}-eks-ca-certificate"
  description = "EKS cluster certificate authority data for Lambda authentication"
  kms_key_id  = aws_kms_key.eks_encryption.arn

  tags = merge(var.tags, {
    "Purpose" = "eks-authentication"
  })
}

resource "aws_secretsmanager_secret_version" "eks_ca_data" {
  secret_id     = aws_secretsmanager_secret.eks_ca_data.id
  secret_string = jsonencode({
    ca_data  = aws_eks_cluster.security_cluster.certificate_authority[0].data
    endpoint = aws_eks_cluster.security_cluster.endpoint
  })
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.cluster_name}-security-alerts"
  kms_master_key_id = aws_kms_key.eks_encryption.id

  tags = var.tags
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.drift_enforcement_lambda_role.arn
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# Lambda function for drift enforcement
resource "aws_lambda_function" "drift_enforcement" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.cluster_name}-drift-enforcement"
  role            = aws_iam_role.drift_enforcement_lambda_role.arn
  handler         = "drift_enforcement_lambda.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime         = "python3.11"
  timeout         = var.lambda_timeout
  memory_size     = var.lambda_memory_size

  environment {
    variables = {
      CLUSTER_NAME               = var.cluster_name
      KISUMU_VPC_CIDRS          = join(",", var.kisumu_vpc_cidrs)
      SNS_TOPIC_ARN             = aws_sns_topic.security_alerts.arn
      QUARANTINE_NAMESPACE      = "security-quarantine"
      EKS_ENDPOINT              = aws_eks_cluster.security_cluster.endpoint
      EKS_CA_SECRET_ARN         = aws_secretsmanager_secret.eks_ca_data.arn
      AWS_DEFAULT_REGION        = var.region
      LOG_LEVEL                 = "INFO"
      REGIONAL_ENFORCEMENT      = var.regional_enforcement_enabled
    }
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  # Lambda layer with Kubernetes client library
  layers = [aws_lambda_layer_version.kubernetes_layer.arn]

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy_attachment.lambda_vpc_execution,
    aws_cloudwatch_log_group.lambda_logs,
  ]

  tags = merge(var.tags, {
    "Function" = "security-enforcement"
  })
}

# Lambda code archive
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda-deployment.zip"

  source {
    content = templatefile("${path.module}/../lambda/drift_enforcement_lambda.py", {
      # Template variables if needed
    })
    filename = "drift_enforcement_lambda.py"
  }

  source {
    content = templatefile("${path.module}/../lambda/tetragon_event_schema.py", {
      # Template variables if needed
    })
    filename = "tetragon_event_schema.py"
  }

  # Requirements file
  source {
    content  = file("${path.module}/../lambda/requirements.txt")
    filename = "requirements.txt"
  }
}

# Lambda layer for Kubernetes client
resource "aws_lambda_layer_version" "kubernetes_layer" {
  filename   = data.archive_file.kubernetes_layer_zip.output_path
  layer_name = "${var.cluster_name}-kubernetes-layer"

  compatible_runtimes = ["python3.11"]
  source_code_hash    = data.archive_file.kubernetes_layer_zip.output_base64sha256

  description = "Kubernetes Python client library for Lambda"
}

# Create Kubernetes layer with dependencies properly installed
resource "null_resource" "build_lambda_layer" {
  triggers = {
    requirements = filemd5("${path.module}/../lambda/requirements.txt")
  }

  provisioner "local-exec" {
    command = <<EOF
      mkdir -p ${path.module}/kubernetes-layer/python
      pip install -r ${path.module}/../lambda/requirements.txt -t ${path.module}/kubernetes-layer/python/
    EOF
  }
}

data "archive_file" "kubernetes_layer_zip" {
  type        = "zip"
  source_dir  = "${path.module}/kubernetes-layer"
  output_path = "${path.module}/kubernetes-layer.zip"

  depends_on = [null_resource.build_lambda_layer]
}

# Security group for Lambda function
resource "aws_security_group" "lambda_sg" {
  name_prefix = "${var.cluster_name}-lambda-"
  description = "Security group for drift enforcement Lambda"
  vpc_id      = var.vpc_id

  # Outbound rules for EKS API access
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS outbound for EKS API and AWS services"
  }

  egress {
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "DNS resolution"
  }

  tags = merge(var.tags, {
    "Name" = "${var.cluster_name}-lambda-sg"
  })
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.cluster_name}-drift-enforcement"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = var.tags
}

# IAM role for Lambda function
resource "aws_iam_role" "drift_enforcement_lambda_role" {
  name = "${var.cluster_name}-drift-enforcement-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM policy for Lambda function
resource "aws_iam_role_policy" "drift_enforcement_lambda_policy" {
  name = "${var.cluster_name}-drift-enforcement-policy"
  role = aws_iam_role.drift_enforcement_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs permissions
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.high_severity_events.arn}:*",
          "${aws_cloudwatch_log_group.process_exec_events.arn}:*",
          "${aws_cloudwatch_log_group.file_access_events.arn}:*",
          "${aws_cloudwatch_log_group.network_events.arn}:*",
          "${aws_cloudwatch_log_group.security_incidents.arn}:*",
          "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
        ]
      },

      # SNS permissions for alerts
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },

      # EKS permissions for API access
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]
        Resource = aws_eks_cluster.security_cluster.arn
      },

      # STS permissions for EKS token generation
      {
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },

      # KMS permissions for encryption/decryption
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.eks_encryption.arn
      },

      # S3 permissions for log archival (optional)
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.security_logs.arn}/*"
      },

      # Secrets Manager permissions for EKS CA data
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.eks_ca_data.arn
      }
    ]
  })
}

# Attach basic execution role
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.drift_enforcement_lambda_role.name
}

# Attach VPC execution role
resource "aws_iam_role_policy_attachment" "lambda_vpc_execution" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
  role       = aws_iam_role.drift_enforcement_lambda_role.name
}

# CloudWatch event rule to trigger Lambda on high-severity events
resource "aws_cloudwatch_event_rule" "high_severity_events" {
  name_prefix = "${var.cluster_name}-high-severity-"
  description = "Trigger Lambda on high-severity security events"

  event_pattern = jsonencode({
    source      = ["aws.logs"]
    detail-type = ["CloudWatch Logs Filter Match"]
    detail = {
      logGroup = [var.high_severity_log_group]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.high_severity_events.name
  target_id = "DriftEnforcementLambdaTarget"
  arn       = aws_lambda_function.drift_enforcement.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_enforcement.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.high_severity_events.arn
}

# CloudWatch Log Stream subscription filter for real-time processing
resource "aws_cloudwatch_log_subscription_filter" "high_severity_filter" {
  name            = "${var.cluster_name}-high-severity-filter"
  log_group_name  = aws_cloudwatch_log_group.high_severity_events.name
  filter_pattern  = "[timestamp, request_id, event_type=\"PROCESS_EXEC\" || event_type=\"FILE\" || event_type=\"NETWORK\", ...]"
  destination_arn = aws_lambda_function.drift_enforcement.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}

resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_enforcement.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.high_severity_events.arn}:*"
}

# Lambda function for automated remediation testing
resource "aws_lambda_function" "remediation_test" {
  filename         = data.archive_file.test_lambda_zip.output_path
  function_name    = "${var.cluster_name}-remediation-test"
  role            = aws_iam_role.drift_enforcement_lambda_role.arn
  handler         = "test_remediation.lambda_handler"
  source_code_hash = data.archive_file.test_lambda_zip.output_base64sha256
  runtime         = "python3.11"
  timeout         = 60

  environment {
    variables = {
      MAIN_LAMBDA_NAME = aws_lambda_function.drift_enforcement.function_name
      CLUSTER_NAME     = var.cluster_name
    }
  }

  tags = merge(var.tags, {
    "Function" = "remediation-testing"
  })
}

data "archive_file" "test_lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/test-lambda.zip"

  source {
    content = templatefile("${path.module}/../lambda/test_remediation.py", {
      # Template variables
    })
    filename = "test_remediation.py"
  }

  source {
    content = templatefile("${path.module}/../lambda/tetragon_event_schema.py", {
      # Template variables
    })
    filename = "tetragon_event_schema.py"
  }
}