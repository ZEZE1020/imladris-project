variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones for subnets"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "eks_version" {
  description = "EKS cluster version"
  type        = string
  default     = "1.28"
}

variable "identity_center_instance_arn" {
  description = "AWS IAM Identity Center instance ARN"
  type        = string
}

# Harbor Secure Registry Configuration
variable "harbor_instance_type" {
  description = "EC2 instance type for Harbor registry"
  type        = string
  default     = "t3.large"
}

variable "harbor_storage_size_gb" {
  description = "Size of encrypted EBS volume for Harbor data storage in GB"
  type        = number
  default     = 100
}

variable "enable_harbor_trivy_scanner" {
  description = "Enable Trivy vulnerability scanner in Harbor"
  type        = bool
  default     = true
}