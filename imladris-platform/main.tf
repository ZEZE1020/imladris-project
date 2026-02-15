# Imladris Platform - Main Infrastructure
# Principal Cloud Architect: Zero Trust Investment Bank Platform

# Networking Module - VPC Lattice Foundation
module "networking" {
  source = "./modules/networking"

  environment        = var.environment
  vpc_cidr          = var.vpc_cidr
  availability_zones = var.availability_zones
}

# Governance Module - Policy Enforcement & Auto-Remediation
module "governance" {
  source = "./modules/governance"

  environment          = var.environment
  vpc_id               = module.networking.vpc_id
  deploy_k8s_resources = false  # Set to true after EKS cluster is created (Phase 2)
}

# Secure Registry Module - Harbor Pull-Through Cache (DISABLED - conflicts with Fargate-only policy)
# Uncomment to deploy Harbor registry (requires policy exemption for EC2)
# module "secure_registry" {
#   source = "./modules/secure-registry"
#
#   environment        = var.environment
#   vpc_id            = module.networking.vpc_id
#   private_subnet_ids = module.networking.private_subnet_ids
#
#   # CI/CD and build environments that need access to Harbor
#   cicd_subnet_ids  = module.networking.private_subnet_ids
#   build_subnet_ids = module.networking.private_subnet_ids
#
#   # Harbor configuration
#   instance_type                   = var.harbor_instance_type
#   storage_size_gb                = var.harbor_storage_size_gb
#   enable_trivy_scanner           = var.enable_harbor_trivy_scanner
#   scan_on_push                   = true
#   block_critical_vulnerabilities = true
#
#   depends_on = [
#     module.networking,
#     module.governance
#   ]
# }

# Compute Module - EKS Fargate Cluster
module "compute" {
  source = "./modules/compute"

  environment                    = var.environment
  vpc_id                        = module.networking.vpc_id
  private_subnet_ids            = module.networking.private_subnet_ids
  vpc_lattice_service_network_id = module.networking.vpc_lattice_service_network_id
  eks_version                   = var.eks_version
  identity_center_instance_arn  = var.identity_center_instance_arn
  vpc_cidr                      = var.vpc_cidr
  aws_region                    = var.aws_region
  eks_cluster_name              = "imladris-${var.environment}-cluster"

  depends_on = [
    module.networking,
    module.governance
  ]
}

# Ingress Module - PrivateLink-Based External Access (OPTIONAL)
# Enables partner/client connectivity WITHOUT an Internet Gateway.
# Uncomment when you have an ACM certificate and want to expose services.
#
# module "ingress" {
#   source = "./modules/ingress"
#
#   environment        = var.environment
#   vpc_id             = module.networking.vpc_id
#   vpc_cidr           = var.vpc_cidr
#   private_subnet_ids = module.networking.private_subnet_ids
#   certificate_arn    = var.ingress_certificate_arn
#
#   # Zero Trust: require manual approval for PrivateLink connections
#   require_manual_acceptance = true
#
#   # Restrict to specific partner AWS accounts
#   allowed_principal_arns = var.ingress_allowed_principals
#
#   depends_on = [
#     module.networking,
#     module.compute
#   ]
# }