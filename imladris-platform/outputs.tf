output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "vpc_lattice_service_network_id" {
  description = "VPC Lattice Service Network ID"
  value       = module.networking.vpc_lattice_service_network_id
}

output "vpc_lattice_service_network_arn" {
  description = "VPC Lattice Service Network ARN"
  value       = module.networking.vpc_lattice_service_network_arn
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.networking.private_subnet_ids
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.compute.cluster_name
}

output "eks_cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.compute.cluster_endpoint
}

output "eks_cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.compute.cluster_security_group_id
}

output "config_configuration_recorder_name" {
  description = "AWS Config Configuration Recorder name"
  value       = module.governance.config_recorder_name
}

output "eventbridge_rule_name" {
  description = "EventBridge rule name for compliance violations"
  value       = module.governance.eventbridge_rule_name
}

# Secure Registry Module Outputs
output "harbor_registry_url" {
  description = "Harbor registry URL for CI/CD configuration"
  value       = module.secure_registry.harbor_url
  sensitive   = false
}

output "harbor_instance_id" {
  description = "EC2 instance ID of Harbor registry"
  value       = module.secure_registry.harbor_instance_id
}

output "harbor_dockerhub_proxy_url" {
  description = "Docker Hub proxy cache URL for CI/CD builds"
  value       = module.secure_registry.dockerhub_proxy_url
  sensitive   = false
}

output "harbor_admin_password_ssm_parameter" {
  description = "SSM parameter name containing Harbor admin password"
  value       = module.secure_registry.admin_password_ssm_parameter
  sensitive   = false
}