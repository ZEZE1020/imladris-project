output "nlb_arn" {
  description = "ARN of the private Network Load Balancer"
  value       = aws_lb.private_ingress.arn
}

output "nlb_dns_name" {
  description = "DNS name of the NLB (use within VPC only)"
  value       = aws_lb.private_ingress.dns_name
}

output "vpc_endpoint_service_name" {
  description = "VPC Endpoint Service name — share with partners to create PrivateLink endpoints"
  value       = aws_vpc_endpoint_service.banking_api.service_name
}

output "vpc_endpoint_service_id" {
  description = "VPC Endpoint Service ID"
  value       = aws_vpc_endpoint_service.banking_api.id
}

output "target_group_arn" {
  description = "ARN of the NLB target group for registration"
  value       = aws_lb_target_group.banking_api.arn
}

output "ingress_security_group_id" {
  description = "Security group ID for ingress targets"
  value       = aws_security_group.ingress_targets.id
}
