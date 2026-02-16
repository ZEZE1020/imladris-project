#!/bin/bash
# ============================================================================
# IMLADRIS WEBINAR - DEMO COMMAND ALIASES
# Source this file before the webinar: source ./scripts/demo-aliases.sh
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Color codes for demo output
export DEMO_GREEN='\033[0;32m'
export DEMO_RED='\033[0;31m'
export DEMO_YELLOW='\033[1;33m'
export DEMO_CYAN='\033[0;36m'
export DEMO_NC='\033[0m'

# ============================================================================
# ALIAS 1: Policy Validation Demo
# Instead of typing: cd imladris-governance && conftest test --policy policies/terraform tfplan.json
# ============================================================================
run-policy-check() {
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo -e "${DEMO_CYAN}  IMLADRIS: OPA/REGO POLICY VALIDATION${DEMO_NC}"
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo ""
    
    cd "$PROJECT_ROOT/imladris-governance"
    
    # Use mock plan if provided, otherwise use demo plan
    local PLAN_FILE="${1:-$PROJECT_ROOT/demo-data/mock-plans/compliant-plan.json}"
    
    echo -e "📋 Validating Terraform plan against guardrails..."
    echo -e "   Plan file: ${DEMO_YELLOW}$(basename $PLAN_FILE)${DEMO_NC}"
    echo ""
    
    if conftest test --policy policies/terraform "$PLAN_FILE" 2>/dev/null; then
        echo ""
        echo -e "${DEMO_GREEN}✅ All policies passed - Infrastructure is compliant${DEMO_NC}"
    else
        echo ""
        echo -e "${DEMO_RED}❌ Policy violations detected - Deployment blocked${DEMO_NC}"
    fi
    
    cd "$PROJECT_ROOT"
}

# ============================================================================
# ALIAS 2: Show Policy Violation Demo (intentionally fails)
# ============================================================================
run-policy-violation() {
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo -e "${DEMO_CYAN}  DEMO: Attempting to deploy EC2 instance (SHOULD FAIL)${DEMO_NC}"
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo ""
    
    cd "$PROJECT_ROOT/imladris-governance"
    
    echo -e "📋 Developer attempting to add EC2 instance to infrastructure..."
    echo ""
    sleep 1
    
    conftest test --policy policies/terraform "$PROJECT_ROOT/demo-data/mock-plans/ec2-violation-plan.json" 2>/dev/null || true
    
    echo ""
    echo -e "${DEMO_RED}🛑 BLOCKED: Fargate-only policy enforced automatically${DEMO_NC}"
    echo -e "${DEMO_YELLOW}   Zero patching burden maintained ✓${DEMO_NC}"
    
    cd "$PROJECT_ROOT"
}

# ============================================================================
# ALIAS 3: Show Public Ingress Violation (intentionally fails)
# ============================================================================
run-ingress-violation() {
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo -e "${DEMO_CYAN}  DEMO: Attempting to open SSH to internet (SHOULD FAIL)${DEMO_NC}"
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo ""
    
    cd "$PROJECT_ROOT/imladris-governance"
    
    echo -e "📋 Developer attempting to add security group rule: SSH from 0.0.0.0/0..."
    echo ""
    sleep 1
    
    conftest test --policy policies/terraform "$PROJECT_ROOT/demo-data/mock-plans/ssh-violation-plan.json" 2>/dev/null || true
    
    echo ""
    echo -e "${DEMO_RED}🛑 BLOCKED: Zero Trust networking enforced${DEMO_NC}"
    echo -e "${DEMO_YELLOW}   No public ingress allowed - VPC Lattice required ✓${DEMO_NC}"
    
    cd "$PROJECT_ROOT"
}

# ============================================================================
# ALIAS 4: Drift Detection Demo (simulated)
# ============================================================================
run-drift-demo() {
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo -e "${DEMO_CYAN}  DEMO: Automated Drift Detection & Remediation${DEMO_NC}"
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo ""
    
    echo -e "🔍 [T+0s]  ${DEMO_YELLOW}Detecting unauthorized security group change...${DEMO_NC}"
    sleep 1
    
    echo -e "⚡ [T+1s]  ${DEMO_YELLOW}AWS Config rule triggered: 'no-public-ingress'${DEMO_NC}"
    sleep 1
    
    echo -e "📨 [T+2s]  ${DEMO_YELLOW}EventBridge routing to remediation Lambda...${DEMO_NC}"
    sleep 1
    
    echo -e "🔧 [T+3s]  ${DEMO_YELLOW}Lambda executing SSM Automation Document...${DEMO_NC}"
    sleep 1
    
    echo -e "✅ [T+4s]  ${DEMO_GREEN}Security group reverted to compliant state${DEMO_NC}"
    echo ""
    echo -e "${DEMO_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo -e "${DEMO_GREEN}  RESULT: Drift detected and auto-remediated in <5 seconds${DEMO_NC}"
    echo -e "${DEMO_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
}

# ============================================================================
# ALIAS 5: IGW / PrivateLink Violation Demo (NEW — for webinar ingress topic)
# ============================================================================
run-igw-violation() {
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo -e "${DEMO_CYAN}  DEMO: Attempting to add Internet Gateway (SHOULD FAIL)${DEMO_NC}"
    echo -e "${DEMO_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${DEMO_NC}"
    echo ""

    cd "$PROJECT_ROOT/imladris-governance"

    echo -e "📋 Developer attempting to add Internet Gateway + public ALB..."
    echo ""
    sleep 1

    conftest test --policy policies/terraform "$PROJECT_ROOT/demo-data/mock-plans/igw-violation-plan.json" 2>/dev/null || true

    echo ""
    echo -e "${DEMO_RED}🛑 BLOCKED: Zero Trust PrivateLink-only ingress enforced${DEMO_NC}"
    echo -e "${DEMO_YELLOW}   Use AWS PrivateLink for external consumers — no IGW allowed ✓${DEMO_NC}"

    cd "$PROJECT_ROOT"
}

# ============================================================================
# ALIAS 6: Show Architecture Diagram
# ============================================================================
show-architecture() {
    echo -e "${DEMO_CYAN}"
    cat << 'EOF'
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IMLADRIS: ZERO TRUST AWS PLATFORM                        │
│                                                                              │
│   Developer → GitHub → Policy Gate → Terraform → AWS → EKS → Service        │
│                          (OPA)        (IaC)     (Infra) (Fargate)           │
│                                                                              │
├──────────────┬──────────────┬──────────────┬────────────────────────────────┤
│  GOVERNANCE  │  NETWORKING  │   COMPUTE    │         SECURITY               │
├──────────────┼──────────────┼──────────────┼────────────────────────────────┤
│  OPA/Rego    │  VPC Lattice │  EKS Fargate │  AWS Config (6 rules)          │
│  Conftest    │  Private VPC │  No EC2      │  EventBridge + Lambda          │
│  Checkov     │  No IGW      │  KMS Encrypt │  SSM Auto-Remediation          │
│  Trivy       │  VPC Endpts  │  IAM IRSA    │  Identity Center (5 users)     │
└──────────────┴──────────────┴──────────────┴────────────────────────────────┘
EOF
    echo -e "${DEMO_NC}"
}

# ============================================================================
# ALIAS 6: Quick Terraform Commands
# ============================================================================
tf-plan() {
    cd "$PROJECT_ROOT/imladris-platform"
    terraform plan -out=demo.tfplan
    cd "$PROJECT_ROOT"
}

tf-apply() {
    cd "$PROJECT_ROOT/imladris-platform"
    terraform apply demo.tfplan
    cd "$PROJECT_ROOT"
}

# ============================================================================
# ALIAS 7: Service Template Build
# ============================================================================
build-service() {
    echo -e "${DEMO_CYAN}Building banking-core-service container...${DEMO_NC}"
    cd "$PROJECT_ROOT/imladris-service-template"
    docker build -t imladris/banking-core-service:demo .
    echo -e "${DEMO_GREEN}✅ Container built successfully${DEMO_NC}"
    cd "$PROJECT_ROOT"
}

# ============================================================================
# Announce loaded aliases
# ============================================================================
echo -e "${DEMO_GREEN}╔════════════════════════════════════════════════════════════╗${DEMO_NC}"
echo -e "${DEMO_GREEN}║  IMLADRIS WEBINAR ALIASES LOADED                           ║${DEMO_NC}"
echo -e "${DEMO_GREEN}╠════════════════════════════════════════════════════════════╣${DEMO_NC}"
echo -e "${DEMO_GREEN}║  run-policy-check      - Show OPA validation (pass)        ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  run-policy-violation  - Demo EC2 blocked by guardrails    ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  run-ingress-violation - Demo SSH blocked by guardrails    ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  run-igw-violation     - Demo IGW blocked (PrivateLink)    ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  run-drift-demo        - Simulate auto-remediation         ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  show-architecture     - Display zero trust diagram        ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  tf-plan / tf-apply    - Quick Terraform commands          ║${DEMO_NC}"
echo -e "${DEMO_GREEN}║  build-service         - Build service container           ║${DEMO_NC}"
echo -e "${DEMO_GREEN}╚════════════════════════════════════════════════════════════╝${DEMO_NC}"
