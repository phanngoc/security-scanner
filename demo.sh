#!/bin/bash

# demo.sh - Demonstration script for Security Scanner

set -e

echo "=== Security Scanner Demo ==="
echo

# Build the scanner
echo "Building security scanner..."
make build
echo

# Create demo directory if it doesn't exist
mkdir -p demo-results

# Demo 1: Scan vulnerable examples with text output
echo "=== Demo 1: Text Output ==="
./bin/security-scanner --format text examples/
echo

# Demo 2: Scan with JSON output
echo "=== Demo 2: JSON Output ==="
./bin/security-scanner --format json --output demo-results/report.json examples/
echo "JSON report saved to demo-results/report.json"
cat demo-results/report.json | jq '.statistics'
echo

# Demo 3: Scan with SARIF output
echo "=== Demo 3: SARIF Output ==="
./bin/security-scanner --format sarif --output demo-results/report.sarif examples/
echo "SARIF report saved to demo-results/report.sarif"
echo

# Demo 4: Scan with different severity levels
echo "=== Demo 4: High Severity Only ==="
./bin/security-scanner --severity high --format text examples/
echo

# Demo 5: Verbose output
echo "=== Demo 5: Verbose Output ==="
./bin/security-scanner --verbose --format text examples/ | head -50
echo

# Demo 6: Parallel processing
echo "=== Demo 6: Parallel Processing ==="
echo "Scanning with 2 workers:"
time ./bin/security-scanner --parallel 2 examples/ > /dev/null
echo
echo "Scanning with 4 workers:"
time ./bin/security-scanner --parallel 4 examples/ > /dev/null
echo

# Demo 7: Cache functionality
echo "=== Demo 7: Cache Functionality ==="
echo "Scanning with cache enabled (default):"
time ./bin/security-scanner examples/ > /dev/null
echo "Second scan (using cache):"
time ./bin/security-scanner examples/ > /dev/null
echo "Cache directory contents:"
ls -la .cache/ || echo "No cache directory yet"
echo

# Demo 8: Self scan
echo "=== Demo 8: Self Scan ==="
echo "Scanning security scanner source code:"
./bin/security-scanner --severity medium . | grep -E "(FOUND|Total findings|Files scanned)" || true
echo

echo "=== Demo Complete ==="
echo "Check demo-results/ directory for output files:"
ls -la demo-results/
