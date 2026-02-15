variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID to deploy the ingress resources into"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block of the VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for the NLB"
  type        = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate ARN for TLS termination on the NLB"
  type        = string
}

variable "allowed_principal_arns" {
  description = "List of AWS principal ARNs allowed to create PrivateLink endpoints to the banking API"
  type        = list(string)
  default     = []
}

variable "require_manual_acceptance" {
  description = "Whether PrivateLink endpoint connections require manual acceptance"
  type        = bool
  default     = true
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection on the NLB"
  type        = bool
  default     = false
}

variable "enable_access_logging" {
  description = "Enable NLB access logging to S3"
  type        = bool
  default     = true
}
