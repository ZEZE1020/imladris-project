variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs"
  type        = list(string)
}

variable "vpc_lattice_service_network_id" {
  description = "VPC Lattice Service Network ID"
  type        = string
}

variable "eks_version" {
  description = "EKS cluster version"
  type        = string
}

variable "identity_center_instance_arn" {
  description = "AWS IAM Identity Center instance ARN"
  type        = string
}

variable "enable_identity_center_permission_sets" {
  description = "Enable IAM Identity Center permission sets (requires organization-level Identity Center)"
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "eks_cluster_name" {
  description = "EKS cluster name (computed)"
  type        = string
  default     = ""
}