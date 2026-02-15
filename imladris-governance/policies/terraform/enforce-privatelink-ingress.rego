# Enforce PrivateLink-Only Ingress Policy
# Ensures external access uses PrivateLink/VPC Endpoint Services, not IGW or public ALBs

package terraform.ingress

import rego.v1

# Deny creation of Internet Gateways — the core Zero Trust networking rule
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_internet_gateway"
    resource := input.planned_values.root_module.resources[i]

    msg := sprintf("VIOLATION: Internet Gateway '%s' is prohibited. Use AWS PrivateLink for external access.", [resource.address])
}

# Deny creation of NAT Gateways — workloads use VPC Endpoints, not NAT
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_nat_gateway"
    resource := input.planned_values.root_module.resources[i]

    msg := sprintf("VIOLATION: NAT Gateway '%s' is prohibited. Use VPC Endpoints for AWS service access.", [resource.address])
}

# Deny public-facing ALBs — all load balancers must be internal
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_lb"
    resource := input.planned_values.root_module.resources[i]

    resource.values.internal == false

    msg := sprintf("VIOLATION: Load balancer '%s' must be internal. Set internal = true. Use PrivateLink for external consumers.", [resource.address])
}

# Require PrivateLink endpoint services to enforce acceptance
warn contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_vpc_endpoint_service"
    resource := input.planned_values.root_module.resources[i]

    resource.values.acceptance_required == false

    msg := sprintf("WARNING: VPC Endpoint Service '%s' should require manual acceptance for Zero Trust access control.", [resource.address])
}

# Deny subnets with map_public_ip_on_launch
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_subnet"
    resource := input.planned_values.root_module.resources[i]

    resource.values.map_public_ip_on_launch == true

    msg := sprintf("VIOLATION: Subnet '%s' must not assign public IPs. Set map_public_ip_on_launch = false.", [resource.address])
}
