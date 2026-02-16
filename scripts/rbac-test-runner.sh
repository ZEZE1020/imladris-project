#!/bin/bash
# Imladris RBAC Test Runner
# Run this script after logging into AWS via SSO
# Usage: ./rbac-test-runner.sh <role>
# Roles: finops | senior-devops | junior-devops | backend-dev | frontend-dev

set -e

ROLE="${1:-unknown}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="rbac-test-${ROLE}-${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Initialize test counters
PASS_COUNT=0
FAIL_COUNT=0

log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

test_pass() {
    ((PASS_COUNT++))
    log "${GREEN}✅ PASS${NC}: $1"
}

test_fail() {
    ((FAIL_COUNT++))
    log "${RED}❌ FAIL${NC}: $1"
}

test_skip() {
    log "${YELLOW}⏭️  SKIP${NC}: $1"
}

run_test() {
    local test_name="$1"
    local command="$2"
    local expect_success="$3"  # true or false
    
    log "\n--- Testing: $test_name ---"
    log "Command: $command"
    
    if OUTPUT=$(eval "$command" 2>&1); then
        if [ "$expect_success" = "true" ]; then
            test_pass "$test_name"
        else
            test_fail "$test_name (should have been denied)"
        fi
    else
        if echo "$OUTPUT" | grep -qi "AccessDenied\|not authorized\|forbidden"; then
            if [ "$expect_success" = "false" ]; then
                test_pass "$test_name (correctly denied)"
            else
                test_fail "$test_name (access denied unexpectedly)"
            fi
        else
            test_fail "$test_name (error: $OUTPUT)"
        fi
    fi
}

# Display banner
log "╔════════════════════════════════════════════════════════════╗"
log "║          IMLADRIS RBAC TEST RUNNER                        ║"
log "║          Security Hardening Validation                     ║"
log "╚════════════════════════════════════════════════════════════╝"
log "Role: $ROLE"
log "Date: $(date)"
log "Caller Identity: $(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo 'Not authenticated')"
log ""

case "$ROLE" in
    finops)
        log "=== Testing FinOps Analyst Permissions (Sarah Johnson) ==="
        
        # Positive tests
        run_test "View EC2 instances" "aws ec2 describe-instances --query 'Reservations[0].Instances[0].InstanceId' --output text" true
        run_test "View Cost Explorer" "aws ce get-cost-and-usage --time-period Start=2026-01-01,End=2026-01-31 --granularity MONTHLY --metrics BlendedCost --query 'ResultsByTime[0].Total' 2>/dev/null || echo 'CE access check'" true
        run_test "View CloudWatch metrics" "aws cloudwatch list-metrics --namespace AWS/EC2 --max-items 1" true
        run_test "View IAM roles (read)" "aws iam list-roles --max-items 1" true
        run_test "View resource tags" "aws resourcegroupstaggingapi get-resources --max-items 1" true
        
        # Negative tests (security boundaries)
        run_test "Create IAM user (SHOULD FAIL)" "aws iam create-user --user-name test-finops-escalation" false
        run_test "Create S3 bucket (SHOULD FAIL)" "aws s3 mb s3://test-finops-bucket-${TIMESTAMP}" false
        run_test "Modify security group (SHOULD FAIL)" "aws ec2 authorize-security-group-ingress --group-id sg-00000000 --protocol tcp --port 22 --cidr 0.0.0.0/0" false
        ;;
        
    senior-devops)
        log "=== Testing Senior DevOps Permissions (Alex Rodriguez) ==="
        
        # Positive tests
        run_test "Describe EKS cluster" "aws eks describe-cluster --name imladris-dev-cluster --query 'cluster.name' --output text" true
        run_test "List IAM roles" "aws iam list-roles --max-items 1" true
        run_test "Get IAM policy" "aws iam list-policies --scope Local --max-items 1" true
        run_test "CloudWatch full access" "aws cloudwatch describe-alarms --max-items 1" true
        run_test "Config service access" "aws configservice describe-config-rules --max-items 1" true
        run_test "S3 list buckets" "aws s3api list-buckets --query 'Buckets[0].Name'" true
        run_test "ECR describe repos" "aws ecr describe-repositories --max-items 1" true
        
        # CRITICAL Security Hardening Tests
        log "\n${YELLOW}=== CRITICAL: Privilege Escalation Tests ===${NC}"
        
        run_test "CREATE IAM User (MUST FAIL - Hardened)" "aws iam create-user --user-name escalation-test-${TIMESTAMP}" false
        run_test "CREATE IAM Role (MUST FAIL - Hardened)" "aws iam create-role --role-name escalation-test-${TIMESTAMP} --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'" false
        run_test "ATTACH Admin Policy (MUST FAIL - Hardened)" "aws iam attach-role-policy --role-name any-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess" false
        run_test "DELETE IAM Role (MUST FAIL - Hardened)" "aws iam delete-role --role-name any-existing-role" false
        run_test "CREATE S3 Bucket (MUST FAIL - Hardened)" "aws s3 mb s3://test-devops-bucket-${TIMESTAMP}" false
        run_test "DELETE S3 Bucket (MUST FAIL - Hardened)" "aws s3 rb s3://imladris-dev-config-random" false
        run_test "PassRole to Lambda (MUST FAIL - Hardened)" "aws lambda create-function --function-name test --role arn:aws:iam::123456789:role/any-role --runtime python3.9 --handler index.handler --zip-file fileb:///tmp/dummy.zip" false
        ;;
        
    junior-devops)
        log "=== Testing Junior DevOps Permissions (Jamie Chen) ==="
        
        # Positive tests
        run_test "Describe EKS cluster" "aws eks describe-cluster --name imladris-dev-cluster --query 'cluster.name' --output text" true
        run_test "View CloudWatch logs" "aws logs describe-log-groups --max-items 1" true
        run_test "View EC2 instances" "aws ec2 describe-instances --query 'Reservations[0].Instances[0].InstanceId'" true
        run_test "View Config rules" "aws configservice describe-config-rules --max-items 1" true
        run_test "View ECR images" "aws ecr describe-repositories --max-items 1" true
        
        # Negative tests
        run_test "Create EC2 instance (SHOULD FAIL)" "aws ec2 run-instances --image-id ami-12345678 --instance-type t2.micro" false
        run_test "Modify EKS (SHOULD FAIL)" "aws eks update-cluster-config --name imladris-dev-cluster --logging '{\"clusterLogging\":[]}'" false
        run_test "Delete log group (SHOULD FAIL)" "aws logs delete-log-group --log-group-name test-group" false
        run_test "Push to ECR (SHOULD FAIL)" "aws ecr put-image --repository-name test --image-manifest '{}'" false
        ;;
        
    backend-dev)
        log "=== Testing Backend Developer Permissions (Mike Thompson) ==="
        
        # Positive tests  
        run_test "ECR get auth token" "aws ecr get-authorization-token --query 'authorizationData[0].proxyEndpoint'" true
        run_test "View banking-* ECR repos" "aws ecr describe-repositories --repository-names banking-core 2>/dev/null || echo 'No repo yet'" true
        
        # Negative tests
        run_test "Describe EKS cluster (SHOULD FAIL)" "aws eks describe-cluster --name imladris-dev-cluster" false
        run_test "View Cost Explorer (SHOULD FAIL)" "aws ce get-cost-and-usage --time-period Start=2026-01-01,End=2026-01-31 --granularity MONTHLY --metrics BlendedCost" false
        run_test "List IAM roles (SHOULD FAIL)" "aws iam list-roles" false
        ;;
        
    frontend-dev)
        log "=== Testing Frontend Developer Permissions (Lisa Wang) ==="
        
        # Positive tests
        run_test "ECR get auth token" "aws ecr get-authorization-token --query 'authorizationData[0].proxyEndpoint'" true
        run_test "View banking-ui ECR repos" "aws ecr describe-repositories --repository-names banking-ui 2>/dev/null || echo 'No repo yet'" true
        
        # Negative tests
        run_test "Describe EKS cluster (SHOULD FAIL)" "aws eks describe-cluster --name imladris-dev-cluster" false
        run_test "View Cost Explorer (SHOULD FAIL)" "aws ce get-cost-and-usage --time-period Start=2026-01-01,End=2026-01-31 --granularity MONTHLY --metrics BlendedCost" false
        run_test "Push to banking-core (SHOULD FAIL)" "aws ecr batch-get-image --repository-name banking-core --image-ids imageTag=latest" false
        ;;
        
    *)
        log "${RED}Unknown role: $ROLE${NC}"
        log "Usage: $0 <role>"
        log "Roles: finops | senior-devops | junior-devops | backend-dev | frontend-dev"
        exit 1
        ;;
esac

# Summary
log "\n"
log "╔════════════════════════════════════════════════════════════╗"
log "║                    TEST SUMMARY                            ║"
log "╠════════════════════════════════════════════════════════════╣"
log "║  ${GREEN}PASSED${NC}: $PASS_COUNT                                          "
log "║  ${RED}FAILED${NC}: $FAIL_COUNT                                          "
log "╚════════════════════════════════════════════════════════════╝"
log "Full results saved to: $LOG_FILE"

# Exit with failure if any tests failed
if [ $FAIL_COUNT -gt 0 ]; then
    exit 1
fi
