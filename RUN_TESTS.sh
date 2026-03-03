#!/bin/bash
# Test Execution Guide for Raw Files List Fix
# Run this script to validate the fix

set -e

echo "================================================================================"
echo "Raw Files List Fix - Test Execution Guide"
echo "================================================================================"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Step 1: Run Unit Tests${NC}"
echo "--------------------------------------------------------------------------------"
echo "Execute the unit tests that validate the glob pattern fix:"
echo ""
echo "  python3 tests/test_host_files_glob_fix.py"
echo ""
read -p "Press Enter to run unit tests..."
python3 tests/test_host_files_glob_fix.py
echo ""

echo -e "${GREEN}✅ Unit tests completed${NC}"
echo ""

echo -e "${YELLOW}Step 2: Verify Code Changes${NC}"
echo "--------------------------------------------------------------------------------"
echo "The following changes were made to fix the bug:"
echo ""
echo "File: rtphelper/services/capture_service.py"
echo "  • Lines ~1850-1867: Added fallback glob pattern without leading wildcard"
echo "  • Lines ~1875 & ~1887: Enhanced S3 name matching with startswith() check"
echo ""
echo "View detailed analysis:"
echo "  cat ROOT_CAUSE_ANALYSIS.md | less"
echo ""
read -p "Press Enter to continue..."
echo ""

echo -e "${YELLOW}Step 3: Manual Integration Test${NC}"
echo "--------------------------------------------------------------------------------"
echo "To test the fix with the actual application:"
echo ""
echo "1. Start the web server:"
echo "   python3 -m rtphelper.web.app"
echo ""
echo "2. Open browser to http://localhost:8000"
echo ""
echo "3. Start a capture, wait a few seconds, then stop it"
echo ""
echo "4. Verify that the 'Captured RTP Files' list appears after stopping"
echo ""
echo "5. Open browser DevTools (F12) → Console and check for:"
echo "   - 'renderRawFiles called with:' log showing non-empty raw_files"
echo "   - 'After renderRawFiles, rawFiles.hidden: false'"
echo "   - '✅ RAW FILES SHOULD BE VISIBLE' in emergency check"
echo ""
echo "Expected result: File list appears with per-host details in <details> elements"
echo ""

echo -e "${YELLOW}Step 4: Validate with Existing E2E Test Data${NC}"
echo "--------------------------------------------------------------------------------"
echo "Test the fix against real captured data in e2e-tests/:"
echo ""
echo "  python3 scripts/test_host_files_discovery.py"
echo ""
read -p "Press Enter to run discovery test..."
python3 scripts/test_host_files_discovery.py || echo -e "${RED}Note: Script may require running app context${NC}"
echo ""

echo -e "${YELLOW}Step 5: Backend Verification${NC}"
echo "--------------------------------------------------------------------------------"
echo "If issues persist, check backend logs for:"
echo ""
echo "  grep 'Discovered host_ids from filenames' logs/app.log"
echo "  grep 'Refreshed session host files' logs/app.log"
echo "  grep 'Found files for host' logs/app.log"
echo ""
echo "Expected log entries:"
echo "  • 'Discovered host_ids from filenames count=X' (if fallback triggered)"
echo "  • 'Refreshed session host files total_hosts=X total_files=Y' (Y > 0)"
echo "  • 'Found files for host host_id=<id> count=N' (N > 0 for each host)"
echo ""

echo "================================================================================"
echo -e "${GREEN}Test Execution Guide Complete${NC}"
echo "================================================================================"
echo ""
echo "For detailed root cause analysis, see: ROOT_CAUSE_ANALYSIS.md"
echo "For glob pattern validation logic, see: scripts/test_glob_fix.py"
echo ""
echo "If the list still doesn't appear:"
echo "  1. Check browser console logs (critical for frontend debugging)"
echo "  2. Verify data.raw_files is not empty in stop capture response"
echo "  3. Check for CSS conflicts hiding rawFiles element"
echo "  4. Ensure postSection.hidden is false after stop"
echo ""
