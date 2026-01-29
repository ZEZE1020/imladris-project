# Secure Registry Module Outputs

output "harbor_instance_id" {
  description = "EC2 instance ID of Harbor registry"
  value       = aws_instance.harbor_registry.id
}

output "harbor_private_ip" {
  description = "Private IP address of Harbor registry"
  value       = aws_instance.harbor_registry.private_ip
}

output "harbor_elastic_ip" {
  description = "Elastic IP address of Harbor registry"
  value       = aws_eip.harbor_registry.public_ip
}

output "harbor_url" {
  description = "Harbor registry URL for CI/CD configuration"
  value       = "https://${aws_instance.harbor_registry.private_ip}"
}

output "harbor_security_group_id" {
  description = "Security group ID for Harbor registry"
  value       = aws_security_group.harbor_registry.id
}

output "kms_key_id" {
  description = "KMS key ID used for Harbor storage encryption"
  value       = aws_kms_key.registry_storage.id
}

output "kms_key_arn" {
  description = "KMS key ARN used for Harbor storage encryption"
  value       = aws_kms_key.registry_storage.arn
}

output "admin_password_ssm_parameter" {
  description = "SSM parameter name containing Harbor admin password"
  value       = "/${var.environment}/harbor/admin-password"
}

output "dockerhub_proxy_url" {
  description = "Docker Hub proxy cache URL for CI/CD builds"
  value       = "${aws_instance.harbor_registry.private_ip}/dockerhub-proxy"
}

output "log_group_name" {
  description = "CloudWatch log group name for Harbor logs"
  value       = aws_cloudwatch_log_group.harbor_logs.name
}