#!/bin/bash
# ============================================================================
# IMLADRIS WEBINAR - DEMO RESET SCRIPT
# Resets the demo environment to clean state in <10 seconds
# Usage: ./reset_demo.sh [--full] [--yes]
#
# ⚠️  WARNING: This script clears terminal history and screen content.
# ⚠️  Only run this in demo/development environments, not during actual work.
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

log() { echo -e "${CYAN}[DEMO RESET]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# Parse arguments
FULL_RESET=false
SKIP_CONFIRM=false
if [[ "$1" == "--full" ]] || [[ "$2" == "--full" ]]; then
    FULL_RESET=true
fi
if [[ "$1" == "--yes" ]] || [[ "$2" == "--yes" ]]; then
    SKIP_CONFIRM=true
fi

# Confirmation prompt for destructive operations
if [[ "$SKIP_CONFIRM" != "true" ]]; then
    echo ""
    warn "This script will clear terminal history and screen content."
    echo -n "Are you sure you want to continue? [y/N] "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          IMLADRIS WEBINAR - DEMO RESET                     ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

log "Starting demo reset..."

# 1. Clear Terraform plan files
log "Clearing Terraform artifacts..."
rm -f "$PROJECT_ROOT/imladris-platform/"*.tfplan 2>/dev/null || true
rm -f "$PROJECT_ROOT/imladris-platform/tfplan.json" 2>/dev/null || true
success "Terraform plan files cleared"

# 2. Clear any test logs
log "Clearing test logs..."
rm -f "$PROJECT_ROOT/scripts/rbac-test-"*.log 2>/dev/null || true
rm -f "$PROJECT_ROOT/"*.log 2>/dev/null || true
success "Test logs cleared"

# 3. Reset demo data files (if any)
log "Resetting demo data..."
if [[ -f "$PROJECT_ROOT/demo-data/sample-events.json.bak" ]]; then
    cp "$PROJECT_ROOT/demo-data/sample-events.json.bak" "$PROJECT_ROOT/demo-data/sample-events.json"
fi
success "Demo data reset"

# 4. Re-generate Terraform plan for demo (if AWS credentials available)
if [[ "$FULL_RESET" == "true" ]]; then
    log "Generating fresh Terraform plan..."
    cd "$PROJECT_ROOT/imladris-platform"
    if terraform init -backend=false -input=false >/dev/null 2>&1; then
        terraform plan -out=demo.tfplan -input=false 2>/dev/null || warn "Terraform plan skipped (no AWS credentials)"
        if [[ -f demo.tfplan ]]; then
            terraform show -json demo.tfplan > tfplan.json
            success "Terraform plan generated"
        fi
    else
        warn "Terraform init skipped (no backend)"
    fi
    cd "$PROJECT_ROOT"
fi

# 5. Clear terminal history for clean demo
log "Preparing terminal..."
if [[ "$SHELL" == *"zsh"* ]]; then
    fc -p  # Clear zsh history for session
fi
clear

# 6. Display ready state
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          DEMO ENVIRONMENT READY                            ║${NC}"
echo -e "${GREEN}║                                                             ║${NC}"
echo -e "${GREEN}║  Quick Commands:                                           ║${NC}"
echo -e "${GREEN}║    run-policy-check  - Show OPA policy validation          ║${NC}"
echo -e "${GREEN}║    run-drift-demo    - Show drift detection                ║${NC}"
echo -e "${GREEN}║    show-architecture - Display zero trust diagram          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

success "Demo reset complete! Ready for webinar."
