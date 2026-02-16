output "cluster_id" {
  description = "EKS cluster ID"
  value       = aws_eks_cluster.main.cluster_id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = aws_eks_cluster.main.arn
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_version" {
  description = "EKS cluster Kubernetes version"
  value       = aws_eks_cluster.main.version
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_security_group.eks_cluster.id
}

output "fargate_profile_name" {
  description = "EKS Fargate profile name"
  value       = aws_eks_fargate_profile.main.fargate_profile_name
}

output "fargate_profile_arn" {
  description = "EKS Fargate profile ARN"
  value       = aws_eks_fargate_profile.main.arn
}

output "vpc_lattice_service_id" {
  description = "VPC Lattice Service ID for EKS API"
  value       = aws_vpclattice_service.eks_api.id
}

output "vpc_lattice_service_arn" {
  description = "VPC Lattice Service ARN for EKS API"
  value       = aws_vpclattice_service.eks_api.arn
}

output "kms_key_arn" {
  description = "KMS key ARN for EKS encryption"
  value       = aws_kms_key.eks.arn
}

output "identity_center_permission_set_arn" {
  description = "IAM Identity Center Permission Set ARN (empty if Identity Center not configured)"
  value       = length(aws_ssoadmin_permission_set.platform_engineers) > 0 ? aws_ssoadmin_permission_set.platform_engineers[0].arn : ""
}

output "oidc_provider_arn" {
  description = "EKS OIDC provider ARN for IRSA trust relationships"
  value       = aws_iam_openid_connect_provider.eks.arn
}

output "oidc_provider_url" {
  description = "EKS OIDC provider URL without https:// prefix"
  value       = replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")
}