variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for security group rules"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for Aurora subnet group"
  type        = list(string)
}

# ===== AURORA CONFIGURATION =====

variable "engine_version" {
  description = "Aurora PostgreSQL engine version"
  type        = string
  default     = "15.4"
}

variable "database_name" {
  description = "Default database name"
  type        = string
  default     = "imladris"
}

variable "master_username" {
  description = "Master username (password auto-managed by Secrets Manager)"
  type        = string
  default     = "imladris_admin"
}

variable "min_capacity" {
  description = "Minimum ACU for Serverless v2 (0.5 = smallest)"
  type        = number
  default     = 0.5
}

variable "max_capacity" {
  description = "Maximum ACU for Serverless v2"
  type        = number
  default     = 4
}

variable "reader_count" {
  description = "Number of read replicas (0 for dev, 1+ for prod)"
  type        = number
  default     = 0
}

variable "backup_retention_days" {
  description = "Number of days to retain automated backups"
  type        = number
  default     = 7
}

variable "deletion_protection" {
  description = "Enable deletion protection (true for prod)"
  type        = bool
  default     = false
}

# ===== EKS/IRSA CONFIGURATION =====

variable "eks_oidc_provider_arn" {
  description = "EKS OIDC provider ARN for IRSA trust relationship"
  type        = string
}

variable "eks_oidc_provider_url" {
  description = "EKS OIDC provider URL (without https://) for condition keys"
  type        = string
}

variable "app_namespace" {
  description = "Kubernetes namespace for the application pods"
  type        = string
  default     = "banking-core"
}

variable "app_service_account" {
  description = "Kubernetes service account name for IRSA binding"
  type        = string
  default     = "banking-core-service"
}

variable "app_db_username" {
  description = "PostgreSQL username the pods connect as (via IAM auth)"
  type        = string
  default     = "banking_app"
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications (optional)"
  type        = string
  default     = ""
}
