# Variables for Real-Time Infrastructure Drift & Runtime Enforcement Engine

variable "cluster_name" {
  description = "Name of the EKS cluster for security monitoring"
  type        = string
  default     = "security-drift-engine"
}

variable "kubernetes_version" {
  description = "Kubernetes version for EKS cluster"
  type        = string
  default     = "1.28"

  validation {
    condition     = can(regex("^1\\.(2[6-9]|[3-9][0-9])$", var.kubernetes_version))
    error_message = "Kubernetes version must be 1.26 or higher for eBPF support."
  }
}

variable "region" {
  description = "AWS region for the infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID where the EKS cluster will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the EKS cluster"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for worker nodes"
  type        = list(string)
}

variable "public_access_cidrs" {
  description = "CIDR blocks allowed to access EKS API server"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# Node Group Configuration
variable "node_instance_types" {
  description = "Instance types for EKS worker nodes (optimized for eBPF workloads)"
  type        = list(string)
  default     = ["m6i.large", "m6i.xlarge"]

  validation {
    condition = alltrue([
      for instance in var.node_instance_types :
      can(regex("^(m6i|m6a|c6i|c6a|r6i|r6a)\\.(large|xlarge|2xlarge|4xlarge)$", instance))
    ])
    error_message = "Instance types must be from 6th generation (m6i, c6i, r6i, etc.) for optimal eBPF performance."
  }
}

variable "desired_nodes" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 3
}

variable "min_nodes" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 2
}

variable "max_nodes" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 10
}

variable "node_disk_size" {
  description = "Disk size for worker nodes in GB"
  type        = number
  default     = 50
}

# Cilium and Tetragon Versions
variable "cilium_version" {
  description = "Version of Cilium CNI to install"
  type        = string
  default     = "1.14.5"
}

variable "tetragon_version" {
  description = "Version of Tetragon to install"
  type        = string
  default     = "1.0.2"
}

# Security Configuration
variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30
}

variable "kms_deletion_window" {
  description = "Number of days for KMS key deletion window"
  type        = number
  default     = 7
}

# Lake Victoria / Kisumu Regional Context
variable "kisumu_vpc_cidrs" {
  description = "CIDR blocks for Lake Victoria/Kisumu regional edge nodes requiring stricter enforcement"
  type        = list(string)
  default     = ["10.100.0.0/16", "172.31.100.0/24"]
}

variable "regional_enforcement_enabled" {
  description = "Enable stricter enforcement for specific regional VPCs"
  type        = bool
  default     = true
}

# Lambda Configuration
variable "lambda_timeout" {
  description = "Timeout for remediation Lambda function in seconds"
  type        = number
  default     = 60
}

variable "lambda_memory_size" {
  description = "Memory allocation for Lambda function in MB"
  type        = number
  default     = 512
}

# CloudWatch Configuration
variable "high_severity_log_group" {
  description = "CloudWatch log group for high-severity security events"
  type        = string
  default     = "/aws/security/drift-engine/high-severity"
}

variable "process_exec_log_group" {
  description = "CloudWatch log group for process execution events"
  type        = string
  default     = "/aws/security/drift-engine/process-exec"
}

variable "file_access_log_group" {
  description = "CloudWatch log group for file access events"
  type        = string
  default     = "/aws/security/drift-engine/file-access"
}

variable "network_events_log_group" {
  description = "CloudWatch log group for network events"
  type        = string
  default     = "/aws/security/drift-engine/network-events"
}

# Process Blacklist Configuration
variable "process_blacklist" {
  description = "List of process names to block with SIGKILL"
  type        = list(string)
  default = [
    "netcat",
    "nc",
    "nmap",
    "wget",
    "curl",
    "apt",
    "apt-get",
    "yum",
    "dnf",
    "pip",
    "pip3",
    "npm",
    "gem",
    "composer",
    "bash",
    "sh",
    "zsh",
    "fish",
    "tcpdump",
    "wireshark",
    "strace",
    "gdb",
    "ssh",
    "scp",
    "rsync",
    "socat",
    "telnet",
    "ftp",
    "tftp"
  ]
}

# File Integrity Monitoring Paths
variable "fim_protected_paths" {
  description = "File system paths to monitor for unauthorized changes"
  type        = list(string)
  default = [
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/boot",
    "/var/lib/kubelet",
    "/var/lib/containerd",
    "/var/lib/docker"
  ]
}

# Network Security Configuration
variable "allowed_egress_cidrs" {
  description = "CIDR blocks allowed for egress traffic"
  type        = list(string)
  default = [
    "10.0.0.0/8",        # Private RFC 1918
    "172.16.0.0/12",     # Private RFC 1918
    "192.168.0.0/16",    # Private RFC 1918
    "169.254.169.254/32" # AWS metadata service
  ]
}

variable "blocked_egress_cidrs" {
  description = "CIDR blocks to block for egress traffic (suspicious/malicious)"
  type        = list(string)
  default = [
    "0.0.0.0/0" # Block all by default - whitelist specific ranges
  ]
}

# Fluent-bit Configuration
variable "fluent_bit_version" {
  description = "Version of Fluent Bit to deploy"
  type        = string
  default     = "2.2.0"
}

variable "fluent_bit_buffer_size" {
  description = "Buffer size for Fluent Bit in MB"
  type        = string
  default     = "32MB"
}

variable "fluent_bit_flush_interval" {
  description = "Flush interval for Fluent Bit in seconds"
  type        = number
  default     = 5
}

# Tags
variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Environment     = "production"
    Project         = "security-drift-engine"
    Owner          = "devsecops-team"
    ManagedBy      = "terraform"
    SecurityLevel  = "critical"
    eBPFEnabled    = "true"
    ComplianceReq  = "zero-trust"
  }
}