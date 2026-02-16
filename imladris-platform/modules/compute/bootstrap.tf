# EKS Bootstrap Module - Deploys ArgoCD and initial services via CodeBuild
# Runs inside VPC to access private EKS endpoint

# Grant CodeBuild access to EKS cluster
resource "aws_eks_access_entry" "codebuild" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.codebuild_role.arn
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "codebuild" {
  cluster_name  = aws_eks_cluster.main.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = aws_iam_role.codebuild_role.arn

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.codebuild]
}

resource "aws_codebuild_project" "eks_bootstrap" {
  name          = "imladris-eks-bootstrap"
  description   = "Bootstrap EKS cluster with ArgoCD and initial services"
  build_timeout = 30
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "EKS_CLUSTER_NAME"
      value = var.eks_cluster_name
    }

    environment_variable {
      name  = "AWS_REGION"
      value = var.aws_region
    }

    # Base64-encoded Kubernetes manifests to avoid YAML escaping issues
    environment_variable {
      name  = "BANKING_DEPLOYMENT_B64"
      value = base64encode(yamlencode({
        apiVersion = "apps/v1"
        kind       = "Deployment"
        metadata = {
          name      = "banking-core"
          namespace = "banking-core"
        }
        spec = {
          replicas = 1
          selector = {
            matchLabels = {
              app = "banking-core"
            }
          }
          template = {
            metadata = {
              labels = {
                app = "banking-core"
              }
            }
            spec = {
              containers = [{
                name  = "banking-core"
                image = "nginx:alpine"
                ports = [{
                  containerPort = 80
                }]
                resources = {
                  requests = {
                    cpu    = "256m"
                    memory = "512Mi"
                  }
                }
              }]
            }
          }
        }
      }))
    }

    environment_variable {
      name  = "BANKING_SERVICE_B64"
      value = base64encode(yamlencode({
        apiVersion = "v1"
        kind       = "Service"
        metadata = {
          name      = "banking-core"
          namespace = "banking-core"
        }
        spec = {
          selector = {
            app = "banking-core"
          }
          ports = [{
            port       = 80
            targetPort = 80
          }]
        }
      }))
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = <<-BUILDSPEC
      version: 0.2
      phases:
        install:
          commands:
            - echo "Installing kubectl..."
            - curl -LO "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl"
            - chmod +x kubectl && mv kubectl /usr/local/bin/
            - kubectl version --client
        pre_build:
          commands:
            - echo "Configuring kubectl for EKS..."
            - aws eks update-kubeconfig --region $AWS_REGION --name $EKS_CLUSTER_NAME
            - echo "Testing connection..."
            - kubectl get nodes || echo "No nodes yet (Fargate)"
        build:
          commands:
            - echo "Creating namespaces..."
            - kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
            - kubectl create namespace banking-core --dry-run=client -o yaml | kubectl apply -f -
            - kubectl create namespace banking-ui --dry-run=client -o yaml | kubectl apply -f -
            - echo "Installing ArgoCD..."
            - kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
            - echo "Waiting for ArgoCD pods..."
            - sleep 30
            - kubectl get pods -n argocd
            - echo "Deploying banking-core service..."
            - echo $BANKING_DEPLOYMENT_B64 | base64 -d | kubectl apply -f -
            - echo "Creating service..."
            - echo $BANKING_SERVICE_B64 | base64 -d | kubectl apply -f -
            - echo "Waiting for Fargate to schedule pods..."
            - sleep 60
            - echo "=== DEPLOYMENT STATUS ==="
            - kubectl get nodes
            - kubectl get pods -A
            - kubectl get svc -A
            - echo "=== ArgoCD Admin Password ==="
            - kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>/dev/null | base64 -d || echo "ArgoCD not ready yet"
            - echo ""
        post_build:
          commands:
            - echo "Bootstrap complete!"
            - echo "View pods in EKS Console -> Resources -> Pods"
    BUILDSPEC
  }

  vpc_config {
    vpc_id             = var.vpc_id
    subnets            = var.private_subnet_ids
    security_group_ids = [aws_security_group.codebuild.id]
  }

  logs_config {
    cloudwatch_logs {
      group_name  = "/aws/codebuild/imladris-eks-bootstrap"
      stream_name = "bootstrap"
    }
  }

  tags = {
    Name        = "imladris-eks-bootstrap"
    Environment = var.environment
  }
}

# Security Group for CodeBuild
resource "aws_security_group" "codebuild" {
  name_prefix = "imladris-codebuild-"
  description = "Security group for CodeBuild EKS bootstrap project"  # Trivy: AVD-AWS-0099
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow all traffic within VPC"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [data.aws_prefix_list.s3.id]
    description = "S3 for CodeBuild artifacts"
  }

  tags = {
    Name = "imladris-codebuild-sg"
  }
}

data "aws_prefix_list" "s3" {
  filter {
    name   = "prefix-list-name"
    values = ["com.amazonaws.${var.aws_region}.s3"]
  }
}

# IAM Role for CodeBuild
resource "aws_iam_role" "codebuild_role" {
  name = "imladris-codebuild-eks-bootstrap"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "codebuild_policy" {
  name = "imladris-codebuild-eks-policy"
  role = aws_iam_role.codebuild_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]
        Resource = "arn:aws:eks:${var.aws_region}:${data.aws_caller_identity.current.account_id}:cluster/imladris-*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/codebuild/imladris-*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeDhcpOptions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterfacePermission"
        ]
        Resource = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:network-interface/*"
        Condition = {
          StringEquals = {
            "ec2:AuthorizedService" = "codebuild.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = [
          "arn:aws:s3:::imladris-*",
          "arn:aws:s3:::codepipeline-*"
        ]
      }
    ]
  })
}

# Using existing data.aws_caller_identity.current from iam-identity-center.tf

# Add CodeBuild role to EKS aws-auth ConfigMap
# This allows CodeBuild to use kubectl
output "codebuild_role_arn" {
  value       = aws_iam_role.codebuild_role.arn
  description = "Add this role to EKS aws-auth ConfigMap for kubectl access"
}

output "bootstrap_command" {
  value       = "aws codebuild start-build --project-name imladris-eks-bootstrap --region ${var.aws_region}"
  description = "Run this command to bootstrap the cluster"
}
