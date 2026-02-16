# ===== CLUSTER CONNECTIVITY =====

output "cluster_endpoint" {
  description = "Aurora cluster writer endpoint"
  value       = aws_rds_cluster.main.endpoint
}

output "cluster_reader_endpoint" {
  description = "Aurora cluster reader endpoint"
  value       = aws_rds_cluster.main.reader_endpoint
}

output "cluster_port" {
  description = "Aurora cluster port"
  value       = aws_rds_cluster.main.port
}

# ===== IDENTIFIERS =====

output "cluster_identifier" {
  description = "Aurora cluster identifier"
  value       = aws_rds_cluster.main.cluster_identifier
}

output "cluster_resource_id" {
  description = "Aurora cluster resource ID (used for IAM auth policy)"
  value       = aws_rds_cluster.main.cluster_resource_id
}

output "database_name" {
  description = "Default database name"
  value       = aws_rds_cluster.main.database_name
}

# ===== SECURITY =====

output "db_access_role_arn" {
  description = "IAM role ARN for pod-level database access (annotate K8s service account)"
  value       = aws_iam_role.db_access.arn
}

output "security_group_id" {
  description = "Security group ID for the Aurora cluster"
  value       = aws_security_group.aurora.id
}

output "kms_key_arn" {
  description = "KMS key ARN used for encryption at rest"
  value       = aws_kms_key.aurora.arn
}

output "master_secret_arn" {
  description = "Secrets Manager ARN for auto-managed master password"
  value       = aws_rds_cluster.main.master_user_secret[0].secret_arn
}
