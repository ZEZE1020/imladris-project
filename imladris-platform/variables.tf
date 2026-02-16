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
  default     = "1.30"
}

variable "identity_center_instance_arn" {
  description = "AWS IAM Identity Center instance ARN (optional - leave empty to skip Identity Center setup)"
  type        = string
  default     = ""
}

# ===== Aurora Serverless v2 =====

variable "aurora_engine_version" {
  description = "Aurora PostgreSQL engine version"
  type        = string
  default     = "15.4"
}

variable "aurora_database_name" {
  description = "Default database name for the Aurora cluster"
  type        = string
  default     = "imladris"
}

variable "aurora_min_capacity" {
  description = "Minimum ACU for Aurora Serverless v2 (0.5 is smallest)"
  type        = number
  default     = 0.5
}

variable "aurora_max_capacity" {
  description = "Maximum ACU for Aurora Serverless v2"
  type        = number
  default     = 4
}

variable "aurora_reader_count" {
  description = "Number of Aurora read replicas (0 for dev, 1+ for prod)"
  type        = number
  default     = 0
}