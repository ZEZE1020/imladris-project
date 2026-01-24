# Deny Public Ingress Policy
# Prevents any security group from allowing ingress from 0.0.0.0/0

package terraform.security

import rego.v1

# Deny public SSH access (port 22)
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_security_group_rule"
    resource := input.planned_values.root_module.resources[i]

    resource.values.type == "ingress"
    resource.values.from_port <= 22
    resource.values.to_port >= 22
    "0.0.0.0/0" in resource.values.cidr_blocks

    msg := sprintf("VIOLATION: Security group rule '%s' allows SSH (port 22) from 0.0.0.0/0", [resource.address])
}

# Deny public HTTP access (port 80)
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_security_group_rule"
    resource := input.planned_values.root_module.resources[i]

    resource.values.type == "ingress"
    resource.values.from_port <= 80
    resource.values.to_port >= 80
    "0.0.0.0/0" in resource.values.cidr_blocks

    msg := sprintf("VIOLATION: Security group rule '%s' allows HTTP (port 80) from 0.0.0.0/0", [resource.address])
}

# Deny public HTTPS access (port 443) - Only VPC Lattice allowed
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_security_group_rule"
    resource := input.planned_values.root_module.resources[i]

    resource.values.type == "ingress"
    resource.values.from_port <= 443
    resource.values.to_port >= 443
    "0.0.0.0/0" in resource.values.cidr_blocks

    # Exception: Allow if this is for VPC Lattice service
    not is_vpc_lattice_service(resource)

    msg := sprintf("VIOLATION: Security group rule '%s' allows HTTPS (port 443) from 0.0.0.0/0. Use VPC Lattice instead.", [resource.address])
}

# Deny public RDP access (port 3389)
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_security_group_rule"
    resource := input.planned_values.root_module.resources[i]

    resource.values.type == "ingress"
    resource.values.from_port <= 3389
    resource.values.to_port >= 3389
    "0.0.0.0/0" in resource.values.cidr_blocks

    msg := sprintf("VIOLATION: Security group rule '%s' allows RDP (port 3389) from 0.0.0.0/0", [resource.address])
}

# Deny any unrestricted ingress
deny contains msg if {
    some i
    input.planned_values.root_module.resources[i].type == "aws_security_group_rule"
    resource := input.planned_values.root_module.resources[i]

    resource.values.type == "ingress"
    resource.values.from_port == 0
    resource.values.to_port == 65535
    "0.0.0.0/0" in resource.values.cidr_blocks

    msg := sprintf("VIOLATION: Security group rule '%s' allows all traffic from 0.0.0.0/0", [resource.address])
}

# Helper function to identify VPC Lattice services
is_vpc_lattice_service(resource) if {
    contains(resource.address, "vpc_lattice")
}

is_vpc_lattice_service(resource) if {
    resource.values.description
    contains(resource.values.description, "VPC Lattice")
}