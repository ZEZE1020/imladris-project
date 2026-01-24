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