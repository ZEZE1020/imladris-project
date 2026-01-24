output "config_recorder_name" {
  description = "Name of the Config configuration recorder"
  value       = aws_config_configuration_recorder.recorder.name
}

output "config_bucket_name" {
  description = "Name of the S3 bucket for Config"
  value       = aws_s3_bucket.config.bucket
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule for compliance violations"
  value       = aws_cloudwatch_event_rule.config_compliance.name
}

output "ssm_document_name" {
  description = "Name of the SSM automation document"
  value       = aws_ssm_document.remediate_ssh.name
}

output "config_role_arn" {
  description = "ARN of the Config service role"
  value       = aws_iam_role.config_role.arn
}

output "eventbridge_role_arn" {
  description = "ARN of the EventBridge service role"
  value       = aws_iam_role.eventbridge_role.arn
}