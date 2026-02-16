# Runtime Security and Automated Remediation
# Zero Trust Banking Platform

# ===== RUNTIME SECURITY =====
# Note: Kubernetes resources require deploy_k8s_resources = true
# Deploy these AFTER the EKS cluster is created (Phase 2)

# Falco for Runtime Threat Detection
resource "kubernetes_namespace_v1" "falco_system" {
  count = var.deploy_k8s_resources ? 1 : 0

  metadata {
    name = "falco-system"
    labels = {
      "pod-security.kubernetes.io/enforce" = "privileged"
      "pod-security.kubernetes.io/audit"   = "privileged"
      "pod-security.kubernetes.io/warn"    = "privileged"
    }
  }
}

# Falco DaemonSet for Runtime Security
resource "kubernetes_manifest" "falco_daemonset" {
  count = var.deploy_k8s_resources ? 1 : 0
  manifest = {
    apiVersion = "apps/v1"
    kind       = "DaemonSet"
    metadata = {
      name      = "falco"
      namespace = "falco-system"
      labels = {
        app = "falco"
      }
    }
    spec = {
      selector = {
        matchLabels = {
          app = "falco"
        }
      }
      template = {
        metadata = {
          labels = {
            app = "falco"
          }
        }
        spec = {
          serviceAccountName = "falco"
          hostNetwork        = true
          hostPID           = true
          containers = [{
            name  = "falco"
            image = "falcosecurity/falco-no-driver:0.36.2"
            args = [
              "/usr/bin/falco",
              "--cri", "/run/containerd/containerd.sock",
              "--k8s-api", "https://kubernetes.default.svc",
              "--k8s-api-cert", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
              "--k8s-api-token-file", "/var/run/secrets/kubernetes.io/serviceaccount/token"
            ]
            securityContext = {
              privileged = true
            }
            volumeMounts = [
              {
                name      = "containerd-socket"
                mountPath = "/run/containerd/containerd.sock"
              },
              {
                name      = "proc"
                mountPath = "/host/proc"
                readOnly  = true
              },
              {
                name      = "boot"
                mountPath = "/host/boot"
                readOnly  = true
              },
              {
                name      = "lib-modules"
                mountPath = "/host/lib/modules"
                readOnly  = true
              },
              {
                name      = "usr"
                mountPath = "/host/usr"
                readOnly  = true
              },
              {
                name      = "etc"
                mountPath = "/host/etc"
                readOnly  = true
              }
            ]
          }]
          volumes = [
            {
              name = "containerd-socket"
              hostPath = {
                path = "/run/containerd/containerd.sock"
              }
            },
            {
              name = "proc"
              hostPath = {
                path = "/proc"
              }
            },
            {
              name = "boot"
              hostPath = {
                path = "/boot"
              }
            },
            {
              name = "lib-modules"
              hostPath = {
                path = "/lib/modules"
              }
            },
            {
              name = "usr"
              hostPath = {
                path = "/usr"
              }
            },
            {
              name = "etc"
              hostPath = {
                path = "/etc"
              }
            }
          ]
          tolerations = [
            {
              effect   = "NoSchedule"
              operator = "Exists"
            }
          ]
        }
      }
    }
  }
}

# ===== AUTOMATED REMEDIATION =====

# Lambda function for automated security remediation
resource "aws_lambda_function" "security_remediation" {
  filename         = "security_remediation.zip"
  function_name    = "imladris-security-remediation"
  role            = aws_iam_role.lambda_remediation_role.arn
  handler         = "index.handler"
  runtime         = "python3.11"
  timeout         = 300
  reserved_concurrent_executions = 10
  kms_key_arn     = aws_kms_key.lambda_env.arn

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  environment {
    variables = {
      EKS_CLUSTER_NAME = "imladris-${var.environment}-cluster"
      SNS_TOPIC_ARN    = aws_sns_topic.security_alerts.arn
    }
  }

  tags = {
    Name = "imladris-security-remediation"
  }
}

# Lambda function code for security remediation
data "archive_file" "remediation_lambda_zip" {
  type        = "zip"
  output_path = "security_remediation.zip"
  source {
    content = <<EOF
import json
import boto3
import os
from datetime import datetime

def handler(event, context):
    """
    Automated security remediation for Imladris platform
    """
    
    # Initialize AWS clients
    ec2 = boto3.client('ec2')
    eks = boto3.client('eks')
    sns = boto3.client('sns')
    config = boto3.client('config')
    
    cluster_name = os.environ['EKS_CLUSTER_NAME']
    sns_topic = os.environ['SNS_TOPIC_ARN']
    
    try:
        # Parse the incoming event
        detail = event.get('detail', {})
        config_rule_name = detail.get('configRuleName', '')
        resource_type = detail.get('resourceType', '')
        resource_id = detail.get('resourceId', '')
        compliance_type = detail.get('newEvaluationResult', {}).get('complianceType', '')
        
        print(f"Processing compliance violation: {config_rule_name} for {resource_type}:{resource_id}")
        
        remediation_actions = []
        
        # Remediate security group violations
        if resource_type == 'AWS::EC2::SecurityGroup' and compliance_type == 'NON_COMPLIANT':
            if 'ssh' in config_rule_name.lower() or 'public' in config_rule_name.lower():
                remediation_actions.append(remediate_security_group(ec2, resource_id))
        
        # Remediate EKS violations
        elif resource_type == 'AWS::EKS::Cluster' and compliance_type == 'NON_COMPLIANT':
            remediation_actions.append(remediate_eks_cluster(eks, resource_id))
        
        # Send notification
        message = {
            'timestamp': datetime.utcnow().isoformat(),
            'rule': config_rule_name,
            'resource': f"{resource_type}:{resource_id}",
            'compliance': compliance_type,
            'actions': remediation_actions
        }
        
        sns.publish(
            TopicArn=sns_topic,
            Subject=f"Imladris Security Remediation: {config_rule_name}",
            Message=json.dumps(message, indent=2)
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Remediation completed',
                'actions': remediation_actions
            })
        }
        
    except Exception as e:
        print(f"Error in remediation: {str(e)}")
        
        # Send error notification
        sns.publish(
            TopicArn=sns_topic,
            Subject="Imladris Security Remediation Error",
            Message=f"Failed to remediate {resource_type}:{resource_id}. Error: {str(e)}"
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def remediate_security_group(ec2, sg_id):
    """
    Remove public access from security groups
    """
    try:
        # Get security group details
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = response['SecurityGroups'][0]
        
        actions = []
        
        # Remove rules allowing 0.0.0.0/0 access
        for rule in sg.get('IpPermissions', []):
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[rule]
                    )
                    actions.append(f"Removed public ingress rule: {rule}")
        
        return {
            'resource': sg_id,
            'type': 'security_group_remediation',
            'actions': actions,
            'status': 'success'
        }
        
    except Exception as e:
        return {
            'resource': sg_id,
            'type': 'security_group_remediation',
            'error': str(e),
            'status': 'failed'
        }

def remediate_eks_cluster(eks, cluster_name):
    """
    Remediate EKS cluster security violations
    """
    try:
        # Get cluster details
        response = eks.describe_cluster(name=cluster_name)
        cluster = response['cluster']
        
        actions = []
        
        # Check if public endpoint is enabled
        vpc_config = cluster.get('resourcesVpcConfig', {})
        if vpc_config.get('endpointConfig', {}).get('publicAccess', False):
            # Disable public access (this would require careful planning in production)
            actions.append("WARNING: EKS public endpoint detected - manual review required")
        
        # Check logging configuration
        logging = cluster.get('logging', {})
        if not logging.get('clusterLogging', []):
            # Enable logging
            eks.update_cluster_config(
                name=cluster_name,
                logging={
                    'clusterLogging': [
                        {
                            'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
                            'enabled': True
                        }
                    ]
                }
            )
            actions.append("Enabled EKS cluster logging")
        
        return {
            'resource': cluster_name,
            'type': 'eks_cluster_remediation',
            'actions': actions,
            'status': 'success'
        }
        
    except Exception as e:
        return {
            'resource': cluster_name,
            'type': 'eks_cluster_remediation',
            'error': str(e),
            'status': 'failed'
        }
EOF
    filename = "index.py"
  }
}

# IAM role for Lambda remediation function
resource "aws_iam_role" "lambda_remediation_role" {
  name = "imladris-lambda-remediation-role"

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
}

# IAM policy for Lambda remediation
resource "aws_iam_role_policy" "lambda_remediation_policy" {
  name = "imladris-lambda-remediation-policy"
  role = aws_iam_role.lambda_remediation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:security-group/*"
      },
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:UpdateClusterConfig"
        ]
        Resource = "arn:aws:eks:*:${data.aws_caller_identity.current.account_id}:cluster/imladris-*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "config:GetComplianceDetailsByConfigRule"
        ]
        Resource = "arn:aws:config:*:${data.aws_caller_identity.current.account_id}:config-rule/*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.lambda_dlq.arn
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# SNS topic for security alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "imladris-security-alerts"
  kms_master_key_id = aws_kms_key.sns_encryption.arn

  tags = {
    Name = "imladris-security-alerts"
  }
}

# KMS key for SNS topic encryption
resource "aws_kms_key" "sns_encryption" {
  description             = "CMK for SNS security alerts topic encryption"
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
        Sid    = "Allow SNS Service"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow EventBridge"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "imladris-sns-encryption-key"
  }
}

# KMS key for Lambda environment variable encryption
resource "aws_kms_key" "lambda_env" {
  description             = "CMK for Lambda environment variable encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "imladris-lambda-env-key"
  }
}

# SQS Dead Letter Queue for Lambda
resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "imladris-security-remediation-dlq"
  kms_master_key_id          = aws_kms_key.sns_encryption.arn
  message_retention_seconds  = 1209600  # 14 days

  tags = {
    Name = "imladris-security-remediation-dlq"
  }
}

# EventBridge rule for Config compliance changes
resource "aws_cloudwatch_event_rule" "config_compliance_remediation" {
  name        = "imladris-config-compliance-remediation"
  description = "Trigger remediation on Config compliance violations"

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

# EventBridge target for Lambda remediation
resource "aws_cloudwatch_event_target" "lambda_remediation_target" {
  rule      = aws_cloudwatch_event_rule.config_compliance_remediation.name
  target_id = "ImladrisRemediationTarget"
  arn       = aws_lambda_function.security_remediation.arn
}

# Lambda permission for EventBridge
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance_remediation.arn
}

# ===== ENHANCED CONFIG RULES =====

# Config rule for SSH access detection
resource "aws_config_config_rule" "no_ssh_access" {
  name = "imladris-no-ssh-access"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

# Config rule for public S3 buckets
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "imladris-s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

# Config rule for EKS endpoint configuration
resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  name = "imladris-eks-endpoint-no-public-access"

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

# Config rule for root access key check
resource "aws_config_config_rule" "root_access_key_check" {
  name = "imladris-root-access-key-check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

# ===== CONTAINER IMAGE SCANNING =====

# ECR repositories with scan on push
resource "aws_ecr_repository" "banking_core" {
  name                 = "banking-core-service"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr_encryption.arn
  }

  tags = {
    Name = "banking-core-service"
  }
}

resource "aws_ecr_repository" "banking_ui" {
  name                 = "banking-ui-service"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr_encryption.arn
  }

  tags = {
    Name = "banking-ui-service"
  }
}

# KMS key for ECR repository encryption
resource "aws_kms_key" "ecr_encryption" {
  description             = "CMK for ECR repository encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "imladris-ecr-encryption-key"
  }
}

# ECR lifecycle policy to manage image retention
resource "aws_ecr_lifecycle_policy" "banking_core_lifecycle" {
  repository = aws_ecr_repository.banking_core.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 production images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["prod"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Keep last 5 development images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["dev"]
          countType     = "imageCountMoreThan"
          countNumber   = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# ===== OUTPUTS =====

output "security_remediation_function_arn" {
  description = "ARN of the security remediation Lambda function"
  value       = aws_lambda_function.security_remediation.arn
}

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "ecr_repositories" {
  description = "ECR repository URLs"
  value = {
    banking_core = aws_ecr_repository.banking_core.repository_url
    banking_ui   = aws_ecr_repository.banking_ui.repository_url
  }
}