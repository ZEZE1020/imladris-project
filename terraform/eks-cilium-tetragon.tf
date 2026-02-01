# Real-Time Infrastructure Drift & Runtime Enforcement Engine
# EKS Cluster with Cilium CNI and Tetragon eBPF Security

# Data sources for latest EKS and AMI versions
data "aws_eks_cluster_auth" "cluster" {
  name = aws_eks_cluster.security_cluster.name
}

data "aws_ami" "eks_worker" {
  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.kubernetes_version}-v*"]
  }
  most_recent = true
  owners      = ["602401143452"] # Amazon EKS AMI Account ID
}

# EKS Cluster optimized for eBPF workloads
resource "aws_eks_cluster" "security_cluster" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.public_access_cidrs
  }

  # Enable advanced logging for security monitoring
  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  # Encryption at rest
  encryption_config {
    provider {
      key_arn = aws_kms_key.eks_encryption.arn
    }
    resources = ["secrets"]
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_resource_controller,
    aws_cloudwatch_log_group.eks_cluster,
  ]

  tags = merge(var.tags, {
    "Security-Engine" = "Cilium-Tetragon"
    "eBPF-Enabled"   = "true"
  })
}

# CloudWatch Log Group for EKS cluster logs
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.eks_encryption.arn

  tags = var.tags
}

# EKS Node Group with BTF support for advanced eBPF capabilities
resource "aws_eks_node_group" "security_nodes" {
  cluster_name    = aws_eks_cluster.security_cluster.name
  node_group_name = "${var.cluster_name}-security-nodes"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = var.private_subnet_ids

  # Instance types optimized for eBPF workloads
  instance_types = var.node_instance_types

  # AMI type that supports BTF (BPF Type Format)
  ami_type       = "AL2_x86_64" # Amazon Linux 2 with BTF support
  capacity_type  = "ON_DEMAND"
  disk_size      = var.node_disk_size

  scaling_config {
    desired_size = var.desired_nodes
    max_size     = var.max_nodes
    min_size     = var.min_nodes
  }

  update_config {
    max_unavailable = 1
  }

  # Enable container runtime security features
  launch_template {
    id      = aws_launch_template.security_nodes.id
    version = aws_launch_template.security_nodes.latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_container_registry,
  ]

  tags = merge(var.tags, {
    "NodeGroup"      = "security-optimized"
    "BTF-Enabled"    = "true"
    "eBPF-Ready"     = "true"
  })
}

# Launch template for security-optimized nodes
resource "aws_launch_template" "security_nodes" {
  name_prefix = "${var.cluster_name}-security-lt-"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  monitoring {
    enabled = true
  }

  # User data for BTF and security optimizations
  user_data = base64encode(templatefile("${path.module}/userdata.sh", {
    cluster_name        = aws_eks_cluster.security_cluster.name
    cluster_endpoint    = aws_eks_cluster.security_cluster.endpoint
    cluster_ca          = aws_eks_cluster.security_cluster.certificate_authority[0].data
    bootstrap_arguments = "--container-runtime containerd --b64-cluster-ca ${aws_eks_cluster.security_cluster.certificate_authority[0].data} --apiserver-endpoint ${aws_eks_cluster.security_cluster.endpoint}"
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      "Name"         = "${var.cluster_name}-security-node"
      "eBPF-Optimized" = "true"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# KMS key for EKS encryption
resource "aws_kms_key" "eks_encryption" {
  description             = "KMS key for EKS cluster encryption"
  deletion_window_in_days = var.kms_deletion_window
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
        Sid    = "Allow EKS Service"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(var.tags, {
    "Purpose" = "EKS-Encryption"
  })
}

resource "aws_kms_alias" "eks_encryption" {
  name          = "alias/${var.cluster_name}-eks-encryption"
  target_key_id = aws_kms_key.eks_encryption.key_id
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Cilium CNI Installation via Helm
resource "helm_release" "cilium" {
  name             = "cilium"
  repository       = "https://helm.cilium.io/"
  chart            = "cilium"
  version          = var.cilium_version
  namespace        = "kube-system"
  create_namespace = false

  # Wait for EKS cluster to be ready
  depends_on = [
    aws_eks_cluster.security_cluster,
    aws_eks_node_group.security_nodes
  ]

  values = [
    yamlencode({
      # Cilium Configuration for kube-proxy replacement
      kubeProxyReplacement = "strict"
      k8sServiceHost       = split("//", aws_eks_cluster.security_cluster.endpoint)[1]
      k8sServicePort       = 443

      # eBPF-based features
      bpf = {
        masquerade    = true
        tproxy        = true
        hostRouting   = true
        # Enable BTF for CO-RE (Compile Once - Run Everywhere)
        lbExternalClusterIP = true
      }

      # Enable Hubble for observability
      hubble = {
        enabled = true
        metrics = {
          enabled = [
            "dns",
            "drop",
            "tcp",
            "flow",
            "port-distribution",
            "icmp",
            "http"
          ]
        }
        relay = {
          enabled = true
        }
        ui = {
          enabled = true
        }
      }

      # Security features
      policyEnforcementMode = "always"

      # Enable host firewall for node-level protection
      hostFirewall = {
        enabled = true
      }

      # Load balancing configuration
      loadBalancer = {
        algorithm = "maglev"
      }

      # IPv4/IPv6 configuration
      ipv4 = {
        enabled = true
      }
      ipv6 = {
        enabled = false
      }

      # Operator configuration
      operator = {
        replicas = 2
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
        }
      }

      # Agent resources
      resources = {
        requests = {
          cpu    = "100m"
          memory = "512Mi"
        }
        limits = {
          cpu    = "4000m"
          memory = "4Gi"
        }
      }

      # Node selector for security-optimized nodes
      nodeSelector = {
        "eBPF-Ready" = "true"
      }

      # Tolerations for system workloads
      tolerations = [
        {
          operator = "Exists"
        }
      ]
    })
  ]

  # Timeout for complex eBPF program loading
  timeout = 600

  # Ensure proper cleanup order
  lifecycle {
    prevent_destroy = false
  }
}

# Tetragon Runtime Security via Helm
resource "helm_release" "tetragon" {
  name             = "tetragon"
  repository       = "https://helm.cilium.io/"
  chart            = "tetragon"
  version          = var.tetragon_version
  namespace        = "kube-system"
  create_namespace = false

  # Ensure Cilium is installed first
  depends_on = [
    helm_release.cilium
  ]

  values = [
    yamlencode({
      # Tetragon Configuration for Runtime Security
      tetragon = {
        # Enable host process monitoring with privileged access
        hostPID = true

        # Enable BTF for CO-RE eBPF programs
        btf = "/sys/kernel/btf/vmlinux"

        # Process monitoring configuration
        processCacheSize = 65536

        # Export configuration
        export = {
          # Enable JSON export for telemetry pipeline
          filename = "/var/log/tetragon/tetragon.log"
          rateLimit = 1000  # Events per second limit
          fieldFilters = [
            # Filter for high-severity events only
            {
              eventSet = ["PROCESS_EXEC", "PROCESS_EXIT"]
              fields   = {
                "process.binary" = ".*"
                "process.arguments" = ".*"
              }
            },
            {
              eventSet = ["FILE"]
              fields   = {
                "file.path" = "^(/etc|/bin|/lib|/usr/bin|/usr/lib).*"
              }
            }
          ]
        }

        # gRPC API configuration for external integrations
        grpc = {
          enabled = true
          address = "localhost:54321"
        }

        # Metrics configuration
        metrics = {
          enabled = true
          port    = 2112
        }

        # Enable process credential tracking
        enableProcessCred = true

        # Enable process namespace tracking
        enableProcessNs = true

        # Enable K8s metadata enrichment
        enableK8sApi = true

        # Kernel symbol resolution
        kernelSymbols = "/proc/kallsyms"
      }

      # Pod security context for privileged eBPF operations
      podSecurityContext = {
        runAsUser = 0
        fsGroup   = 0
      }

      # Container security context
      securityContext = {
        privileged = true
        capabilities = {
          add = [
            "SYS_ADMIN",    # Required for eBPF operations
            "SYS_RESOURCE", # Required for memory locking
            "SYS_PTRACE",   # Required for process tracing
            "NET_ADMIN",    # Required for network monitoring
            "IPC_LOCK",     # Required for BPF map pinning
            "SYS_BOOT"      # Required for kernel access
          ]
        }
        readOnlyRootFilesystem = false
      }

      # Resource allocation
      resources = {
        requests = {
          cpu    = "500m"
          memory = "1Gi"
        }
        limits = {
          cpu    = "2000m"
          memory = "4Gi"
        }
      }

      # Node selector for security-optimized nodes
      nodeSelector = {
        "eBPF-Ready" = "true"
      }

      # Tolerations for system workloads
      tolerations = [
        {
          operator = "Exists"
        }
      ]

      # Host network access for kernel monitoring
      hostNetwork = true

      # Mount host filesystem for monitoring
      extraHostPathMounts = [
        {
          name      = "sys-fs-bpf"
          mountPath = "/sys/fs/bpf"
          hostPath  = "/sys/fs/bpf"
          readOnly  = false
        },
        {
          name      = "proc"
          mountPath = "/host/proc"
          hostPath  = "/proc"
          readOnly  = true
        },
        {
          name      = "sys"
          mountPath = "/host/sys"
          hostPath  = "/sys"
          readOnly  = true
        },
        {
          name      = "var-log"
          mountPath = "/var/log/tetragon"
          hostPath  = "/var/log/tetragon"
          readOnly  = false
        }
      ]

      # Priority class for critical security workloads
      priorityClassName = "system-node-critical"

      # Enable automatic policy loading
      policyDirectory = "/etc/tetragon/policies"
    })
  ]

  timeout = 600

  lifecycle {
    prevent_destroy = false
  }
}

# IAM Roles and Policies
resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.cluster_name}-cluster-role"

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

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "eks_vpc_resource_controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role" "eks_node_role" {
  name = "${var.cluster_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_container_registry" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}

# Custom IAM policy for CloudWatch integration
resource "aws_iam_role_policy" "node_cloudwatch_policy" {
  name = "${var.cluster_name}-node-cloudwatch-policy"
  role = aws_iam_role.eks_node_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}