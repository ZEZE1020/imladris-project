#!/bin/bash
# ============================================================================
# IMLADRIS WEBINAR - PRE-FLIGHT CHECKLIST
# Run this 30 minutes before the webinar to verify everything works
# Usage: ./scripts/preflight-check.sh
# ============================================================================

# Don't exit on error - we want to report all issues
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

check_pass() { ((PASS_COUNT++)); echo -e "${GREEN}✅ PASS${NC}: $1"; }
check_fail() { ((FAIL_COUNT++)); echo -e "${RED}❌ FAIL${NC}: $1"; }
check_warn() { ((WARN_COUNT++)); echo -e "${YELLOW}⚠️  WARN${NC}: $1"; }

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          IMLADRIS WEBINAR - PRE-FLIGHT CHECKLIST           ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================================
# PHASE 1: Essential Tools
# ============================================================================
echo -e "${CYAN}━━━ PHASE 1: Essential Tools ━━━${NC}"

# Check Terraform
if command -v terraform &> /dev/null; then
    TF_VERSION=$(terraform version -json 2>/dev/null | jq -r '.terraform_version' 2>/dev/null || terraform version | head -1)
    check_pass "Terraform installed: $TF_VERSION"
else
    check_fail "Terraform not found - install from terraform.io"
fi

# Check Conftest
if command -v conftest &> /dev/null; then
    CONFTEST_VERSION=$(conftest --version 2>/dev/null | head -1)
    check_pass "Conftest installed: $CONFTEST_VERSION"
else
    check_fail "Conftest not found - required for OPA policy demo"
fi

# Check Docker
if command -v docker &> /dev/null; then
    if docker ps &> /dev/null; then
        check_pass "Docker running"
    else
        check_warn "Docker installed but not running"
    fi
else
    check_warn "Docker not found - container build demo will be skipped"
fi

# Check AWS CLI
if command -v aws &> /dev/null; then
    AWS_VERSION=$(aws --version 2>/dev/null | cut -d' ' -f1)
    check_pass "AWS CLI installed: $AWS_VERSION"
else
    check_warn "AWS CLI not found - AWS demos will use mock data"
fi

# Check kubectl
if command -v kubectl &> /dev/null; then
    check_pass "kubectl installed"
else
    check_warn "kubectl not found - K8s demos will be simulated"
fi

echo ""

# ============================================================================
# PHASE 2: Project Files
# ============================================================================
echo -e "${CYAN}━━━ PHASE 2: Project Files ━━━${NC}"

# Check demo scripts
if [[ -x "$SCRIPT_DIR/reset_demo.sh" ]]; then
    check_pass "reset_demo.sh exists and executable"
else
    check_fail "reset_demo.sh missing or not executable"
fi

if [[ -x "$SCRIPT_DIR/demo-aliases.sh" ]]; then
    check_pass "demo-aliases.sh exists and executable"
else
    check_fail "demo-aliases.sh missing or not executable"
fi

# Check mock plans
if [[ -f "$PROJECT_ROOT/demo-data/mock-plans/compliant-plan.json" ]]; then
    check_pass "Mock plan files present"
else
    check_fail "Mock plan files missing - policy demo will fail"
fi

# Check OPA policies
if [[ -f "$PROJECT_ROOT/imladris-governance/policies/terraform/deny-public-ingress.rego" ]]; then
    check_pass "OPA policies present"
else
    check_fail "OPA policies missing"
fi

# Check .env.demo
if [[ -f "$PROJECT_ROOT/.env.demo" ]]; then
    check_pass ".env.demo configuration present"
else
    check_warn ".env.demo missing - demo mode may not work"
fi

echo ""

# ============================================================================
# PHASE 3: Connectivity Tests
# ============================================================================
echo -e "${CYAN}━━━ PHASE 3: Connectivity (Optional) ━━━${NC}"

# Test internet connectivity
if ping -c 1 google.com &> /dev/null; then
    check_pass "Internet connectivity OK"
else
    check_warn "No internet - demo will use offline mode"
fi

# Test GitHub (for repo fetches)
if curl -s --connect-timeout 5 https://api.github.com &> /dev/null; then
    check_pass "GitHub API reachable"
else
    check_warn "GitHub unreachable - code will be served locally"
fi

echo ""

# ============================================================================
# PHASE 4: Policy Validation Test
# ============================================================================
echo -e "${CYAN}━━━ PHASE 4: Demo Functionality Test ━━━${NC}"

# Test Conftest with mock plan
if command -v conftest &> /dev/null; then
    cd "$PROJECT_ROOT/imladris-governance"
    
    # Test compliant plan (should pass)
    if conftest test --policy policies/terraform "$PROJECT_ROOT/demo-data/mock-plans/compliant-plan.json" &> /dev/null; then
        check_pass "Policy validation works (compliant plan passes)"
    else
        check_warn "Compliant plan failed - check policy syntax"
    fi
    
    # Test violation plan (should fail)
    if ! conftest test --policy policies/terraform "$PROJECT_ROOT/demo-data/mock-plans/ec2-violation-plan.json" &> /dev/null; then
        check_pass "Policy enforcement works (EC2 violation blocked)"
    else
        check_warn "EC2 violation not blocked - check enforce-fargate.rego"
    fi
    
    cd "$PROJECT_ROOT"
fi

# Test Python demo wrapper
if python3 -c "from lambda.demo_mode_wrapper import get_demo_response; print('OK')" &> /dev/null; then
    check_pass "Python demo wrapper importable"
else
    check_warn "Python demo wrapper has issues"
fi

echo ""

# ============================================================================
# SUMMARY
# ============================================================================
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}                    PRE-FLIGHT SUMMARY${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}Passed${NC}:  $PASS_COUNT"
echo -e "  ${YELLOW}Warnings${NC}: $WARN_COUNT"
echo -e "  ${RED}Failed${NC}:  $FAIL_COUNT"
echo ""

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ READY FOR WEBINAR!                                     ║${NC}"
    echo -e "${GREEN}║                                                             ║${NC}"
    echo -e "${GREEN}║  Quick Start:                                              ║${NC}"
    echo -e "${GREEN}║    1. source scripts/demo-aliases.sh                       ║${NC}"
    echo -e "${GREEN}║    2. source .env.demo                                     ║${NC}"
    echo -e "${GREEN}║    3. ./scripts/reset_demo.sh                              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ ISSUES DETECTED - FIX BEFORE WEBINAR                   ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
fi
echo ""
