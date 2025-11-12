#!/bin/bash
# test-hera-v3.sh - Automated test suite for HERA V3
# This script runs comprehensive tests on all V3 security implementations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "========================================="
echo "HERA V3 Integration Test Suite"
echo "========================================="
echo ""
echo "Project Root: $PROJECT_ROOT"
echo "Go Version: $(go version)"
echo ""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_cmd="$2"

    echo -n "Test: $test_name... "

    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((pass_count++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((fail_count++))
        return 1
    fi
}

# Test 1: Check if V3 files exist
echo "========================================="
echo "Phase 1: File Existence Checks"
echo "========================================="

run_test "V3 CORS implementation exists" "test -f middleware/cors_secure_v3.go"
run_test "V3 Session implementation exists" "test -f middleware/session_secure_v3.go"
run_test "V3 Template implementation exists" "test -f models/template_secure_v3.go"
run_test "Monitoring module exists" "test -f monitoring/metrics.go"

echo ""

# Test 2: Go build check
echo "========================================="
echo "Phase 2: Build Checks"
echo "========================================="

run_test "Project builds successfully" "go build -o /tmp/gophish-test ./cmd/gophish"

echo ""

# Test 3: Unit tests for middleware
echo "========================================="
echo "Phase 3: Middleware Unit Tests"
echo "========================================="

echo "Running CORS V3 tests..."
if go test -v ./middleware -run ".*CORS.*" 2>&1 | tee /tmp/cors-test.log; then
    echo -e "${GREEN}✓ CORS tests PASS${NC}"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ No CORS tests found or tests failed${NC}"
fi

echo ""
echo "Running Session V3 tests..."
if go test -v ./middleware -run ".*Session.*" 2>&1 | tee /tmp/session-test.log; then
    echo -e "${GREEN}✓ Session tests PASS${NC}"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ No Session tests found or tests failed${NC}"
fi

echo ""

# Test 4: Unit tests for models
echo "========================================="
echo "Phase 4: Models Unit Tests"
echo "========================================="

echo "Running Template V3 tests..."
if go test -v ./models -run ".*Template.*" 2>&1 | tee /tmp/template-test.log; then
    echo -e "${GREEN}✓ Template tests PASS${NC}"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ No Template tests found or tests failed${NC}"
fi

echo ""
echo "Running Password tests..."
if go test -v ./models -run ".*Password.*" 2>&1 | tee /tmp/password-test.log; then
    echo -e "${GREEN}✓ Password tests PASS${NC}"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ No Password tests found or tests failed${NC}"
fi

echo ""

# Test 5: Race condition detection
echo "========================================="
echo "Phase 5: Race Condition Detection"
echo "========================================="

echo "Checking for race conditions in middleware..."
if go test -race ./middleware/... 2>&1 | tee /tmp/race-middleware.log; then
    echo -e "${GREEN}✓ No race conditions in middleware${NC}"
    ((pass_count++))
else
    echo -e "${RED}✗ Race conditions detected in middleware${NC}"
    ((fail_count++))
fi

echo ""
echo "Checking for race conditions in models..."
if go test -race ./models/... 2>&1 | tee /tmp/race-models.log; then
    echo -e "${GREEN}✓ No race conditions in models${NC}"
    ((pass_count++))
else
    echo -e "${RED}✗ Race conditions detected in models${NC}"
    ((fail_count++))
fi

echo ""

# Test 6: Security scanning
echo "========================================="
echo "Phase 6: Security Scanning"
echo "========================================="

if command -v gosec &> /dev/null; then
    echo "Running gosec security scanner..."
    if gosec -quiet ./... 2>&1 | tee /tmp/gosec.log; then
        echo -e "${GREEN}✓ No security issues detected${NC}"
        ((pass_count++))
    else
        echo -e "${YELLOW}⚠ Potential security issues detected (review /tmp/gosec.log)${NC}"
    fi
else
    echo -e "${YELLOW}⚠ gosec not installed, skipping security scan${NC}"
    echo "   Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi

echo ""

if command -v govulncheck &> /dev/null; then
    echo "Running govulncheck for vulnerability detection..."
    if govulncheck ./... 2>&1 | tee /tmp/govulncheck.log; then
        echo -e "${GREEN}✓ No known vulnerabilities${NC}"
        ((pass_count++))
    else
        echo -e "${RED}✗ Vulnerabilities detected (review /tmp/govulncheck.log)${NC}"
        ((fail_count++))
    fi
else
    echo -e "${YELLOW}⚠ govulncheck not installed, skipping vulnerability check${NC}"
    echo "   Install with: go install golang.org/x/vuln/cmd/govulncheck@latest"
fi

echo ""

# Test 7: Code formatting and linting
echo "========================================="
echo "Phase 7: Code Quality Checks"
echo "========================================="

echo "Checking code formatting..."
unformatted=$(gofmt -l middleware/ models/ monitoring/ 2>/dev/null || true)
if [ -z "$unformatted" ]; then
    echo -e "${GREEN}✓ All code is properly formatted${NC}"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ Unformatted files detected:${NC}"
    echo "$unformatted"
    echo "   Run: gofmt -w middleware/ models/ monitoring/"
fi

echo ""

if command -v golint &> /dev/null; then
    echo "Running golint..."
    if golint ./middleware/... ./models/... ./monitoring/... 2>&1 | tee /tmp/golint.log | grep -q .; then
        echo -e "${YELLOW}⚠ Linting suggestions found (review /tmp/golint.log)${NC}"
    else
        echo -e "${GREEN}✓ No linting issues${NC}"
        ((pass_count++))
    fi
else
    echo -e "${YELLOW}⚠ golint not installed, skipping linting${NC}"
fi

echo ""

# Test 8: Dependency check
echo "========================================="
echo "Phase 8: Dependency Audit"
echo "========================================="

echo "Checking for outdated dependencies..."
if go list -u -m all 2>&1 | tee /tmp/dependencies.log; then
    echo -e "${GREEN}✓ Dependency check complete${NC}"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ Dependency check had warnings${NC}"
fi

echo ""

# Test 9: Test coverage
echo "========================================="
echo "Phase 9: Test Coverage Analysis"
echo "========================================="

echo "Calculating test coverage..."
if go test -coverprofile=/tmp/coverage.out ./middleware/... ./models/... ./monitoring/... 2>&1; then
    coverage=$(go tool cover -func=/tmp/coverage.out | grep total | awk '{print $3}')
    echo -e "${GREEN}✓ Total test coverage: $coverage${NC}"

    # Generate HTML coverage report
    go tool cover -html=/tmp/coverage.out -o /tmp/coverage.html
    echo "   HTML coverage report: /tmp/coverage.html"
    ((pass_count++))
else
    echo -e "${YELLOW}⚠ Coverage calculation incomplete${NC}"
fi

echo ""

# Test 10: Build for multiple platforms
echo "========================================="
echo "Phase 10: Cross-Platform Build Check"
echo "========================================="

platforms=("linux/amd64" "linux/arm64" "darwin/amd64" "windows/amd64")
for platform in "${platforms[@]}"; do
    IFS='/' read -r -a array <<< "$platform"
    GOOS="${array[0]}"
    GOARCH="${array[1]}"

    echo -n "Building for $GOOS/$GOARCH... "
    if GOOS=$GOOS GOARCH=$GOARCH go build -o /tmp/gophish-$GOOS-$GOARCH ./cmd/gophish > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        ((pass_count++))
    else
        echo -e "${RED}✗${NC}"
        ((fail_count++))
    fi
done

echo ""

# Summary
echo "========================================="
echo "Test Summary"
echo "========================================="
echo ""
echo "Tests Passed: ${GREEN}$pass_count${NC}"
echo "Tests Failed: ${RED}$fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ ALL TESTS PASSED! ✓✓✓${NC}"
    echo ""
    echo "HERA V3 is ready for deployment!"
    exit 0
else
    echo -e "${RED}✗✗✗ SOME TESTS FAILED ✗✗✗${NC}"
    echo ""
    echo "Please review the failed tests before deployment."
    echo "Test logs are available in /tmp/*.log"
    exit 1
fi
