output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "private_subnet_cidrs" {
  description = "CIDR blocks of the private subnets"
  value       = aws_subnet.private[*].cidr_block
}

output "vpc_lattice_service_network_id" {
  description = "VPC Lattice Service Network ID"
  value       = aws_vpclattice_service_network.main.id
}

output "vpc_lattice_service_network_arn" {
  description = "VPC Lattice Service Network ARN"
  value       = aws_vpclattice_service_network.main.arn
}

output "vpc_endpoints_security_group_id" {
  description = "Security Group ID for VPC Endpoints"
  value       = aws_security_group.vpc_endpoints.id
}