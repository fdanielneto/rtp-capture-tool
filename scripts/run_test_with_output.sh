#!/bin/bash
cd /Users/fdanielneto/Documents/github/rtp-capture-tool
.venv/bin/python scripts/test_new_correlation.py > /tmp/correlation_test_output.txt 2>&1
echo "Output saved to /tmp/correlation_test_output.txt"
cat /tmp/correlation_test_output.txt
