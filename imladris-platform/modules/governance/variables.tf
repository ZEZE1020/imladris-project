variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for governance rules"
  type        = string
}

variable "deploy_k8s_resources" {
  description = "Whether to deploy Kubernetes resources (requires existing EKS cluster)"
  type        = bool
  default     = false
}

variable "eks_cluster_endpoint" {
  description = "EKS cluster endpoint (required if deploy_k8s_resources is true)"
  type        = string
  default     = ""
}

variable "eks_cluster_ca_certificate" {
  description = "EKS cluster CA certificate (required if deploy_k8s_resources is true)"
  type        = string
  default     = ""
}