# Outputs for Real-Time Infrastructure Drift & Runtime Enforcement Engine

# EKS Cluster Information
output "cluster_id" {
  description = "EKS cluster ID"
  value       = aws_eks_cluster.security_cluster.id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = aws_eks_cluster.security_cluster.arn
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.security_cluster.endpoint
  sensitive   = true
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = aws_eks_cluster.security_cluster.vpc_config[0].cluster_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "EKS cluster certificate authority data"
  value       = aws_eks_cluster.security_cluster.certificate_authority[0].data
  sensitive   = true
}

output "cluster_version" {
  description = "EKS cluster Kubernetes version"
  value       = aws_eks_cluster.security_cluster.version
}

# Node Group Information
output "node_group_arn" {
  description = "EKS node group ARN"
  value       = aws_eks_node_group.security_nodes.arn
}

output "node_group_status" {
  description = "EKS node group status"
  value       = aws_eks_node_group.security_nodes.status
}

output "node_instance_types" {
  description = "Instance types used in the node group"
  value       = aws_eks_node_group.security_nodes.instance_types
}

# Cilium and Tetragon Information
output "cilium_release_status" {
  description = "Cilium Helm release status"
  value       = helm_release.cilium.status
}

output "tetragon_release_status" {
  description = "Tetragon Helm release status"
  value       = helm_release.tetragon.status
}

# Lambda Function Information
output "drift_enforcement_lambda_arn" {
  description = "ARN of the drift enforcement Lambda function"
  value       = aws_lambda_function.drift_enforcement.arn
}

output "drift_enforcement_lambda_name" {
  description = "Name of the drift enforcement Lambda function"
  value       = aws_lambda_function.drift_enforcement.function_name
}

output "remediation_test_lambda_arn" {
  description = "ARN of the remediation test Lambda function"
  value       = aws_lambda_function.remediation_test.arn
}

output "remediation_test_lambda_name" {
  description = "Name of the remediation test Lambda function"
  value       = aws_lambda_function.remediation_test.function_name
}

# CloudWatch Information
output "cloudwatch_log_groups" {
  description = "CloudWatch log groups for security events"
  value = {
    high_severity     = aws_cloudwatch_log_group.high_severity_events.name
    process_exec      = aws_cloudwatch_log_group.process_exec_events.name
    file_access       = aws_cloudwatch_log_group.file_access_events.name
    network_events    = aws_cloudwatch_log_group.network_events.name
    security_incidents = aws_cloudwatch_log_group.security_incidents.name
    lambda_logs       = aws_cloudwatch_log_group.lambda_logs.name
  }
}

# SNS Topic Information
output "security_alerts_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "security_alerts_topic_name" {
  description = "Name of the SNS topic for security alerts"
  value       = aws_sns_topic.security_alerts.name
}

# S3 Bucket Information
output "security_logs_bucket_name" {
  description = "Name of the S3 bucket for security log archival"
  value       = aws_s3_bucket.security_logs.bucket
}

output "security_logs_bucket_arn" {
  description = "ARN of the S3 bucket for security log archival"
  value       = aws_s3_bucket.security_logs.arn
}

# KMS Key Information
output "eks_encryption_key_id" {
  description = "KMS key ID used for EKS encryption"
  value       = aws_kms_key.eks_encryption.key_id
}

output "eks_encryption_key_arn" {
  description = "KMS key ARN used for EKS encryption"
  value       = aws_kms_key.eks_encryption.arn
}

# IAM Role Information
output "eks_cluster_role_arn" {
  description = "ARN of the EKS cluster service role"
  value       = aws_iam_role.eks_cluster_role.arn
}

output "eks_node_role_arn" {
  description = "ARN of the EKS node group role"
  value       = aws_iam_role.eks_node_role.arn
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.drift_enforcement_lambda_role.arn
}

# Regional Context Information
output "kisumu_vpc_cidrs" {
  description = "VPC CIDR blocks for Kisumu regional enforcement"
  value       = var.kisumu_vpc_cidrs
}

output "regional_enforcement_enabled" {
  description = "Whether regional enforcement is enabled"
  value       = var.regional_enforcement_enabled
}

# Security Configuration
output "process_blacklist" {
  description = "List of blacklisted processes"
  value       = var.process_blacklist
}

output "fim_protected_paths" {
  description = "File paths protected by FIM"
  value       = var.fim_protected_paths
}

output "allowed_egress_cidrs" {
  description = "CIDR blocks allowed for egress traffic"
  value       = var.allowed_egress_cidrs
}

# Connection Information
output "kubectl_config_command" {
  description = "Command to configure kubectl"
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${aws_eks_cluster.security_cluster.name}"
}

output "tetragon_logs_access_command" {
  description = "Command to access Tetragon logs"
  value       = "kubectl logs -n kube-system daemonset/tetragon -f"
}

output "fluent_bit_logs_access_command" {
  description = "Command to access Fluent-bit logs"
  value       = "kubectl logs -n kube-system daemonset/fluent-bit -f"
}

# Monitoring and Debugging Commands
output "monitoring_commands" {
  description = "Useful commands for monitoring the security engine"
  value = {
    "view_quarantined_pods" = "kubectl get pods -A -l security.tetragon.io/quarantined=true"
    "view_network_policies" = "kubectl get networkpolicy -A -l security.tetragon.io/quarantine=true"
    "test_remediation" = "aws lambda invoke --function-name ${aws_lambda_function.remediation_test.function_name} --payload '{\"test_type\":\"all\",\"kisumu_region\":true}' response.json && cat response.json"
    "view_security_incidents" = "aws logs describe-log-streams --log-group-name ${aws_cloudwatch_log_group.security_incidents.name}"
    "cilium_status" = "kubectl exec -n kube-system ds/cilium -- cilium status"
    "tetragon_status" = "kubectl exec -n kube-system ds/tetragon -- tetragon status"
  }
}

# eBPF and Kernel Information
output "btf_requirements" {
  description = "BTF (BPF Type Format) requirements"
  value = {
    "kernel_version_minimum" = "5.4+"
    "btf_enabled" = "Required for CO-RE eBPF programs"
    "verification_command" = "ls -la /sys/kernel/btf/vmlinux"
  }
}

# TracingPolicy Deployment Commands
output "tracing_policy_deployment_commands" {
  description = "Commands to deploy TracingPolicy resources"
  value = {
    "deploy_process_enforcement" = "kubectl apply -f k8s/tetragon-policies/process-execution-enforcement.yaml"
    "deploy_file_monitoring" = "kubectl apply -f k8s/tetragon-policies/file-integrity-monitoring.yaml"
    "deploy_network_enforcement" = "kubectl apply -f k8s/tetragon-policies/network-drift-enforcement.yaml"
    "deploy_fluent_bit" = "kubectl apply -f k8s/fluent-bit/fluent-bit-config.yaml"
    "list_policies" = "kubectl get tracingpolicy -A"
  }
}

# Performance and Scaling Information
output "performance_considerations" {
  description = "Performance considerations and limits"
  value = {
    "max_events_per_second" = 1000
    "lambda_concurrent_executions" = 100
    "cloudwatch_logs_retention" = "${var.log_retention_days} days"
    "s3_lifecycle_policy" = "30d IA, 90d Glacier, 365d Deep Archive, 7y deletion"
    "recommended_node_types" = var.node_instance_types
  }
}

# Network Security Zones
output "network_security_zones" {
  description = "Network security zone configuration"
  value = {
    "standard_enforcement" = {
      "description" = "Standard VPC enforcement with basic drift detection"
      "cidr_blocks" = "All VPCs except Kisumu region"
    }
    "enhanced_enforcement" = {
      "description" = "Enhanced enforcement for Kisumu region"
      "cidr_blocks" = var.kisumu_vpc_cidrs
      "restrictions" = [
        "Block all external egress except AWS metadata",
        "DNS only to VPC resolver",
        "Immediate quarantine for any violations"
      ]
    }
  }
}

# Integration Endpoints
output "integration_endpoints" {
  description = "Key integration endpoints for external tools"
  value = {
    "tetragon_grpc_endpoint" = "localhost:54321"
    "hubble_ui_port_forward" = "kubectl port-forward -n kube-system svc/hubble-ui 12000:80"
    "fluent_bit_metrics" = "kubectl port-forward -n kube-system ds/fluent-bit 2020:2020"
    "cilium_metrics" = "kubectl port-forward -n kube-system ds/cilium 9963:9963"
  }
}

# Security Baselines
output "security_baselines" {
  description = "Security baseline configuration applied"
  value = {
    "zero_trust_enforcement" = true
    "default_deny_network_policy" = true
    "privileged_containers_blocked" = true
    "root_filesystem_readonly" = true
    "capability_dropping_enforced" = true
    "seccomp_default_enabled" = true
    "apparmor_enforced" = true
  }
}