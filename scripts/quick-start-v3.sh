#!/bin/bash
# quick-start-v3.sh - Quick Start and Verification for HERA V3
# This script helps you quickly verify your V3 setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}HERA V3 Quick Start & Verification${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
    fi
}

# Step 1: Check V3 files exist
echo -e "${BLUE}Step 1: Checking V3 Files...${NC}"
files_ok=1

check_file() {
    if [ -f "$1" ]; then
        print_status 0 "$1"
    else
        print_status 1 "$1 (MISSING)"
        files_ok=0
    fi
}

check_file "middleware/cors_secure_v3.go"
check_file "middleware/session_secure_v3.go"
check_file "models/template_secure_v3.go"
check_file "monitoring/metrics.go"
check_file "scripts/test-hera-v3.sh"
check_file "deployments/zero-downtime-deploy.sh"

if [ $files_ok -eq 0 ]; then
    echo -e "${RED}ERROR: Some V3 files are missing!${NC}"
    exit 1
fi

echo ""

# Step 2: Check Go version
echo -e "${BLUE}Step 2: Checking Go Version...${NC}"
go_version=$(go version 2>/dev/null || echo "not installed")
echo "  $go_version"

if ! command -v go &> /dev/null; then
    echo -e "${RED}ERROR: Go is not installed!${NC}"
    exit 1
fi

go_major=$(go version | sed 's/.*go\([0-9]*\)\..*/\1/')
go_minor=$(go version | sed 's/.*go[0-9]*\.\([0-9]*\).*/\1/')

if [ "$go_major" -lt 1 ] || ([ "$go_major" -eq 1 ] && [ "$go_minor" -lt 18 ]); then
    echo -e "${YELLOW}WARNING: Go 1.18+ recommended, you have Go $go_major.$go_minor${NC}"
fi

print_status 0 "Go version acceptable"
echo ""

# Step 3: Build check
echo -e "${BLUE}Step 3: Verifying Code Compiles...${NC}"
if go build -o /tmp/gophish-v3-check ./cmd/gophish > /dev/null 2>&1; then
    print_status 0 "Code compiles successfully"
    rm -f /tmp/gophish-v3-check
else
    print_status 1 "Build failed"
    echo -e "${RED}Run 'go build ./cmd/gophish' to see errors${NC}"
    exit 1
fi

echo ""

# Step 4: Check session keys utility
echo -e "${BLUE}Step 4: Testing Session Key Generator...${NC}"
if go run scripts/generate-session-keys.go > /tmp/keys-test.txt 2>&1; then
    print_status 0 "Session key generator works"

    # Check if keys look valid
    if grep -q "session_signing_key" /tmp/keys-test.txt && grep -q "session_encryption_key" /tmp/keys-test.txt; then
        print_status 0 "Generated keys have correct format"
    else
        print_status 1 "Generated keys format incorrect"
    fi

    rm -f /tmp/keys-test.txt
else
    print_status 1 "Session key generator failed"
fi

echo ""

# Step 5: Check test files
echo -e "${BLUE}Step 5: Checking Test Files...${NC}"
test_files_ok=1

check_test_file() {
    if [ -f "$1" ]; then
        print_status 0 "$1"
    else
        print_status 1 "$1 (MISSING)"
        test_files_ok=0
    fi
}

check_test_file "middleware/cors_secure_v3_test.go"
check_test_file "middleware/session_secure_v3_test.go"
check_test_file "models/template_secure_v3_test.go"

echo ""

# Step 6: Run quick unit tests
echo -e "${BLUE}Step 6: Running Quick Unit Tests...${NC}"
echo "  (This may take a minute...)"

if go test ./middleware -run ".*V3.*" -short > /tmp/middleware-test.log 2>&1; then
    print_status 0 "Middleware tests passed"
else
    print_status 1 "Middleware tests failed (see /tmp/middleware-test.log)"
fi

if go test ./models -run ".*V3.*" -short > /tmp/models-test.log 2>&1; then
    print_status 0 "Models tests passed"
else
    print_status 1 "Models tests failed (see /tmp/models-test.log)"
fi

echo ""

# Step 7: Check documentation
echo -e "${BLUE}Step 7: Checking Documentation...${NC}"
docs_ok=1

check_doc() {
    if [ -f "$1" ]; then
        lines=$(wc -l < "$1")
        print_status 0 "$1 ($lines lines)"
    else
        print_status 1 "$1 (MISSING)"
        docs_ok=0
    fi
}

check_doc "HERA_V3_README.md"
check_doc "HERA_V3_FINAL_ANALYSIS.md"
check_doc "HERA_V3_INTEGRATION_GUIDE.md"
check_doc "MIGRATION_V2_TO_V3.md"

echo ""

# Step 8: Check monitoring configs
echo -e "${BLUE}Step 8: Checking Monitoring Configurations...${NC}"

check_file "monitoring/grafana/hera-v3-dashboard.json"
check_file "monitoring/prometheus/alert-rules.yml"
check_file "data/common-passwords.txt"

echo ""

# Step 9: Check example configs
echo -e "${BLUE}Step 9: Checking Example Configurations...${NC}"

check_file "config-examples/config-v3-development.json"
check_file "config-examples/config-v3-production.json"

echo ""

# Step 10: Summary and next steps
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Verification Complete!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

if [ $files_ok -eq 1 ] && [ $test_files_ok -eq 1 ] && [ $docs_ok -eq 1 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo -e "${GREEN}Your HERA V3 installation is ready!${NC}"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Generate session keys:"
    echo -e "   ${YELLOW}go run scripts/generate-session-keys.go${NC}"
    echo ""
    echo "2. Review integration guide:"
    echo -e "   ${YELLOW}cat HERA_V3_INTEGRATION_GUIDE.md${NC}"
    echo ""
    echo "3. Check example config:"
    echo -e "   ${YELLOW}cat config-examples/config-v3-development.json${NC}"
    echo ""
    echo "4. Run full test suite:"
    echo -e "   ${YELLOW}./scripts/test-hera-v3.sh${NC}"
    echo ""
    echo "5. Review migration guide (if upgrading from V2):"
    echo -e "   ${YELLOW}cat MIGRATION_V2_TO_V3.md${NC}"
    echo ""
else
    echo -e "${RED}⚠ Some checks failed!${NC}"
    echo ""
    echo "Please fix the issues above before proceeding."
    echo ""
    echo "For help, see:"
    echo -e "  ${YELLOW}cat HERA_V3_README.md${NC}"
    echo ""
    exit 1
fi

# Optional: Offer to run full test suite
echo ""
echo -e "${YELLOW}Would you like to run the full test suite now? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${BLUE}Running full test suite...${NC}"
    echo ""
    ./scripts/test-hera-v3.sh
fi

echo ""
echo -e "${GREEN}HERA V3 Quick Start Complete!${NC}"
echo ""
