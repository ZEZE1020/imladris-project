# Require VPC Lattice Policy
# Ensures all service-to-service communication uses VPC Lattice

package terraform.networking

import rego.v1

# Warn when creating ALB/NLB without VPC Lattice integration
warn contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_lb"
    resource := input.planned_values.root_module.resources[i]

    resource.values.load_balancer_type == "application"
    resource.values.internal == false

    msg := sprintf("WARNING: Public ALB '%s' detected. Consider using VPC Lattice for internal service communication.", [resource.address])
}

# Require VPC Lattice Service Network for service communication
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_vpclattice_service"
    resource := input.planned_values.root_module.resources[i]

    # Check if there's no associated service network
    not has_service_network_association(resource.address)

    msg := sprintf("VIOLATION: VPC Lattice service '%s' must be associated with a service network", [resource.address])
}

# Require IAM authentication for VPC Lattice services
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_vpclattice_service"
    resource := input.planned_values.root_module.resources[i]

    resource.values.auth_type != "AWS_IAM"

    msg := sprintf("VIOLATION: VPC Lattice service '%s' must use AWS_IAM authentication", [resource.address])
}

# Helper function to check for service network association
has_service_network_association(service_address) if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_vpclattice_service_network_service_association"
    resource := input.planned_values.root_module.resources[i]

    service_ref := sprintf("%s.id", [service_address])
    contains(resource.values.service_identifier, service_ref)
}

# Require encryption in transit for all VPC Lattice services
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_vpclattice_listener"
    resource := input.planned_values.root_module.resources[i]

    resource.values.protocol == "HTTP"

    msg := sprintf("VIOLATION: VPC Lattice listener '%s' must use HTTPS for encryption in transit", [resource.address])
}