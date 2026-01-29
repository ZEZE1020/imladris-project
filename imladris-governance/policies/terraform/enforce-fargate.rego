# Enforce Fargate Policy
# Ensures only Fargate is used for compute - no EC2 instances

package terraform.compute

import rego.v1

# Deny EC2 instances - use Fargate only (with Harbor registry exception)
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_instance"
    resource := input.planned_values.root_module.resources[i]

    # Allow Harbor registry instances for supply chain security
    not is_harbor_registry_instance(resource)

    msg := sprintf("VIOLATION: EC2 instance '%s' is not allowed. Use EKS Fargate for compute. (Harbor registry instances are exempt for supply chain security)", [resource.address])
}

# Deny EKS node groups - use Fargate only
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_eks_node_group"
    resource := input.planned_values.root_module.resources[i]

    msg := sprintf("VIOLATION: EKS node group '%s' is not allowed. Use EKS Fargate profiles only.", [resource.address])
}

# Deny Auto Scaling Groups - use Fargate only
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_autoscaling_group"
    resource := input.planned_values.root_module.resources[i]

    msg := sprintf("VIOLATION: Auto Scaling Group '%s' is not allowed. Use EKS Fargate for auto-scaling.", [resource.address])
}

# Require Fargate profiles for EKS clusters
warn contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_eks_cluster"
    resource := input.planned_values.root_module.resources[i]

    # Check if there's a corresponding Fargate profile
    not has_fargate_profile(resource.values.name)

    msg := sprintf("WARNING: EKS cluster '%s' should have at least one Fargate profile", [resource.address])
}

# Ensure Fargate profiles use private subnets only
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_eks_fargate_profile"
    resource := input.planned_values.root_module.resources[i]

    # Check if any subnet is public
    some subnet_id in resource.values.subnet_ids
    is_public_subnet(subnet_id)

    msg := sprintf("VIOLATION: Fargate profile '%s' cannot use public subnets. Use private subnets only.", [resource.address])
}

# Helper function to check for Fargate profiles
has_fargate_profile(cluster_name) if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_eks_fargate_profile"
    resource := input.planned_values.root_module.resources[i]

    resource.values.cluster_name == cluster_name
}

# Helper function to identify Harbor registry instances (allowed exception)
is_harbor_registry_instance(resource) if {
    # Check if instance has Harbor-related tags or name
    contains(lower(resource.address), "harbor")
}

is_harbor_registry_instance(resource) if {
    # Check if instance is part of secure-registry module
    contains(resource.address, "secure_registry")
}

is_harbor_registry_instance(resource) if {
    # Check tags for Harbor/SecureRegistry purpose
    some tag_key, tag_value in resource.values.tags
    tag_key == "Purpose"
    tag_value == "SecureRegistry"
}

# Helper function to identify public subnets
is_public_subnet(subnet_ref) if {
    # Look for subnets with "public" in the name or tags
    some i
    input.planned_values.root_module.resources[i].type == "aws_subnet"
    resource := input.planned_values.root_module.resources[i]

    subnet_address := sprintf("%s.id", [resource.address])
    contains(subnet_ref, subnet_address)

    contains(lower(resource.address), "public")
}

is_public_subnet(subnet_ref) if {
    # Look for subnets with map_public_ip_on_launch = true
    some i
    input.planned_values.root_module.resources[i].type == "aws_subnet"
    resource := input.planned_values.root_module.resources[i]

    subnet_address := sprintf("%s.id", [resource.address])
    contains(subnet_ref, subnet_address)

    resource.values.map_public_ip_on_launch == true
}