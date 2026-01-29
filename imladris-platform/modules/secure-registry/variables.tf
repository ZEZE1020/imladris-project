# Secure Registry Module Variables

variable "environment" {
  description = "Environment name (e.g., prod, staging, dev)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where Harbor registry will be deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for Harbor deployment"
  type        = list(string)
}

variable "cicd_subnet_ids" {
  description = "CI/CD subnet IDs that need access to Harbor"
  type        = list(string)
  default     = []
}

variable "build_subnet_ids" {
  description = "Build environment subnet IDs that need access to Harbor"
  type        = list(string)
  default     = []
}

variable "instance_type" {
  description = "EC2 instance type for Harbor registry"
  type        = string
  default     = "t3.large"
}

variable "storage_size_gb" {
  description = "Size of encrypted EBS volume for Harbor data storage in GB"
  type        = number
  default     = 100
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access Harbor (for emergency access)"
  type        = list(string)
  default     = []
}

variable "harbor_version" {
  description = "Harbor version to install"
  type        = string
  default     = "v2.9.1"
}

variable "enable_trivy_scanner" {
  description = "Enable Trivy vulnerability scanner in Harbor"
  type        = bool
  default     = true
}

variable "scan_on_push" {
  description = "Enable automatic vulnerability scanning on image push"
  type        = bool
  default     = true
}

variable "block_critical_vulnerabilities" {
  description = "Block deployment of images with critical vulnerabilities"
  type        = bool
  default     = true
}