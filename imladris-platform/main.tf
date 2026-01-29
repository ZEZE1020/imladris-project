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

  environment = var.environment
  vpc_id      = module.networking.vpc_id
}

# Secure Registry Module - Harbor Pull-Through Cache
module "secure_registry" {
  source = "./modules/secure-registry"

  environment        = var.environment
  vpc_id            = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids

  # CI/CD and build environments that need access to Harbor
  cicd_subnet_ids  = module.networking.private_subnet_ids
  build_subnet_ids = module.networking.private_subnet_ids

  depends_on = [
    module.networking,
    module.governance
  ]
}

# Compute Module - EKS Fargate Cluster
module "compute" {
  source = "./modules/compute"

  environment                    = var.environment
  vpc_id                        = module.networking.vpc_id
  private_subnet_ids            = module.networking.private_subnet_ids
  vpc_lattice_service_network_id = module.networking.vpc_lattice_service_network_id
  eks_version                   = var.eks_version
  identity_center_instance_arn  = var.identity_center_instance_arn

  depends_on = [
    module.networking,
    module.governance,
    module.secure_registry
  ]
}