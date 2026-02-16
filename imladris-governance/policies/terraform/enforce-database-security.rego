# Enforce Database Security - Aurora Serverless v2
# Zero Trust: Encryption at rest, IAM auth, no public access

package terraform.database

import rego.v1

# Deny unencrypted Aurora clusters
deny contains msg if {
    cluster := input.resource_changes[_]
    cluster.type == "aws_rds_cluster"
    cluster.change.after.storage_encrypted == false
    msg := sprintf(
        "DENY: Aurora cluster '%s' must have storage encryption enabled (storage_encrypted = true)",
        [cluster.change.after.cluster_identifier]
    )
}

# Deny clusters without IAM authentication
deny contains msg if {
    cluster := input.resource_changes[_]
    cluster.type == "aws_rds_cluster"
    cluster.change.after.iam_database_authentication_enabled == false
    msg := sprintf(
        "DENY: Aurora cluster '%s' must have IAM database authentication enabled — no static passwords in Zero Trust",
        [cluster.change.after.cluster_identifier]
    )
}

# Deny publicly accessible instances
deny contains msg if {
    instance := input.resource_changes[_]
    instance.type == "aws_rds_cluster_instance"
    instance.change.after.publicly_accessible == true
    msg := sprintf(
        "DENY: Aurora instance '%s' must not be publicly accessible",
        [instance.change.after.identifier]
    )
}

# Deny clusters without deletion protection in production
deny contains msg if {
    cluster := input.resource_changes[_]
    cluster.type == "aws_rds_cluster"
    contains(cluster.change.after.cluster_identifier, "prod")
    cluster.change.after.deletion_protection == false
    msg := sprintf(
        "DENY: Production Aurora cluster '%s' must have deletion protection enabled",
        [cluster.change.after.cluster_identifier]
    )
}

# Deny clusters without backup retention
deny contains msg if {
    cluster := input.resource_changes[_]
    cluster.type == "aws_rds_cluster"
    cluster.change.after.backup_retention_period < 7
    msg := sprintf(
        "DENY: Aurora cluster '%s' must have backup retention of at least 7 days (got %d)",
        [cluster.change.after.cluster_identifier, cluster.change.after.backup_retention_period]
    )
}
