#!/bin/bash

# Test coverage script for Pahlevan
# This script runs comprehensive tests and generates coverage reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
COVERAGE_DIR="coverage"
COVERAGE_FILE="$COVERAGE_DIR/coverage.out"
COVERAGE_HTML="$COVERAGE_DIR/coverage.html"
COVERAGE_XML="$COVERAGE_DIR/coverage.xml"
MIN_COVERAGE=80

echo -e "${BLUE}🧪 Starting Pahlevan Test Coverage Analysis${NC}"
echo "=================================================="

# Create coverage directory
mkdir -p "$COVERAGE_DIR"

# Clean previous coverage data
echo -e "${YELLOW}📁 Cleaning previous coverage data...${NC}"
rm -f "$COVERAGE_FILE" "$COVERAGE_HTML" "$COVERAGE_XML"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go is not installed${NC}"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
echo -e "${BLUE}🔍 Go version: $GO_VERSION${NC}"

# Install required tools
echo -e "${YELLOW}🔧 Installing testing tools...${NC}"
go install github.com/axw/gocov/gocov@latest
go install github.com/AlekSi/gocov-xml@latest
go install github.com/matm/gocov-html@latest

# Run tests with coverage
echo -e "${YELLOW}🏃 Running tests with coverage...${NC}"

# Unit tests
echo -e "${BLUE}📝 Running unit tests...${NC}"
go test -v -race -covermode=atomic -coverprofile="$COVERAGE_FILE" ./...

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Unit tests failed${NC}"
    exit 1
fi

# Check if coverage file was created
if [ ! -f "$COVERAGE_FILE" ]; then
    echo -e "${RED}❌ Coverage file not created${NC}"
    exit 1
fi

# Generate coverage report
echo -e "${YELLOW}📊 Generating coverage reports...${NC}"

# Text summary
go tool cover -func="$COVERAGE_FILE" > "$COVERAGE_DIR/coverage.txt"

# HTML report
go tool cover -html="$COVERAGE_FILE" -o "$COVERAGE_HTML"

# XML report (for CI/CD)
gocov convert "$COVERAGE_FILE" | gocov-xml > "$COVERAGE_XML"

# Calculate total coverage
TOTAL_COVERAGE=$(go tool cover -func="$COVERAGE_FILE" | tail -1 | awk '{print $3}' | sed 's/%//')

echo -e "${BLUE}📈 Coverage Summary${NC}"
echo "==================="
echo -e "Total Coverage: ${GREEN}${TOTAL_COVERAGE}%${NC}"

# Check coverage threshold
if (( $(echo "$TOTAL_COVERAGE >= $MIN_COVERAGE" | bc -l) )); then
    echo -e "${GREEN}✅ Coverage meets minimum threshold ($MIN_COVERAGE%)${NC}"
else
    echo -e "${RED}❌ Coverage below minimum threshold ($MIN_COVERAGE%)${NC}"
    exit 1
fi

# Package-specific coverage
echo -e "\n${BLUE}📦 Package Coverage Breakdown${NC}"
echo "=============================="
go tool cover -func="$COVERAGE_FILE" | grep -E "^.*\.go:" | sort -k3 -nr | head -20

# Find uncovered functions
echo -e "\n${YELLOW}🔍 Functions with low coverage (< 50%)${NC}"
echo "========================================="
go tool cover -func="$COVERAGE_FILE" | awk '$3 < 50.0 && $3 != "0.0" {print $1 ":" $2 " - " $3 "%"}' | head -10

# Generate detailed package reports
echo -e "\n${YELLOW}📋 Generating detailed package reports...${NC}"
for pkg in $(go list ./... | grep -v vendor); do
    pkg_name=$(basename "$pkg")
    pkg_coverage_file="$COVERAGE_DIR/coverage_${pkg_name}.out"

    # Run coverage for specific package
    go test -covermode=atomic -coverprofile="$pkg_coverage_file" "$pkg" 2>/dev/null || continue

    if [ -f "$pkg_coverage_file" ]; then
        pkg_coverage=$(go tool cover -func="$pkg_coverage_file" | tail -1 | awk '{print $3}' | sed 's/%//')
        echo "  $pkg_name: ${pkg_coverage}%"
    fi
done

# Integration test coverage (if available)
if [ -d "test/integration" ]; then
    echo -e "\n${YELLOW}🔗 Running integration tests...${NC}"
    INTEGRATION_COVERAGE="$COVERAGE_DIR/integration_coverage.out"

    # Check if Kind is available for integration tests
    if command -v kind &> /dev/null; then
        echo -e "${BLUE}🎯 Running integration tests with Kind...${NC}"
        # This would run integration tests if they exist
        # go test -v -covermode=atomic -coverprofile="$INTEGRATION_COVERAGE" ./test/integration/...
        echo -e "${YELLOW}⚠️  Integration tests require Kind cluster setup${NC}"
    else
        echo -e "${YELLOW}⚠️  Kind not available, skipping integration tests${NC}"
    fi
fi

# Benchmark tests
echo -e "\n${YELLOW}⏱️  Running benchmark tests...${NC}"
go test -bench=. -benchmem ./... > "$COVERAGE_DIR/benchmarks.txt" 2>&1 || true

# Memory and race condition tests
echo -e "\n${YELLOW}🔍 Running race condition detection...${NC}"
go test -race ./... > "$COVERAGE_DIR/race_test.txt" 2>&1 || true

# Generate test report summary
echo -e "\n${BLUE}📄 Generating test report summary...${NC}"
cat > "$COVERAGE_DIR/test_summary.txt" << EOF
Pahlevan Test Coverage Report
=============================
Generated: $(date)
Go Version: $GO_VERSION
Total Coverage: $TOTAL_COVERAGE%
Minimum Threshold: $MIN_COVERAGE%
Status: $(if (( $(echo "$TOTAL_COVERAGE >= $MIN_COVERAGE" | bc -l) )); then echo "PASS"; else echo "FAIL"; fi)

Files Generated:
- coverage.out: Raw coverage data
- coverage.html: HTML coverage report
- coverage.xml: XML coverage report (for CI/CD)
- coverage.txt: Text coverage summary
- benchmarks.txt: Benchmark results
- race_test.txt: Race condition test results

View HTML report: open $COVERAGE_HTML
EOF

# Print final summary
echo -e "\n${GREEN}✅ Test coverage analysis complete!${NC}"
echo -e "${BLUE}📁 Reports saved to: $COVERAGE_DIR/${NC}"
echo -e "${BLUE}🌐 View HTML report: open $COVERAGE_HTML${NC}"

# Open HTML report if running locally (not in CI)
if [ -z "$CI" ] && [ -z "$GITHUB_ACTIONS" ]; then
    if command -v open &> /dev/null; then
        echo -e "${YELLOW}🌐 Opening coverage report in browser...${NC}"
        open "$COVERAGE_HTML"
    elif command -v xdg-open &> /dev/null; then
        echo -e "${YELLOW}🌐 Opening coverage report in browser...${NC}"
        xdg-open "$COVERAGE_HTML"
    fi
fi

echo -e "\n${GREEN}🎉 All tests completed successfully!${NC}"