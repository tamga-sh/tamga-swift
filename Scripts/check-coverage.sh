#!/bin/sh
# Scripts/check-coverage.sh
#
# Gates CI on 80% line coverage for the `Tamga` target. No mature
# off-the-shelf GitHub Action exists for Swift coverage gating, so this is
# hand-written rather than borrowed.
#
# Usage (see .github/workflows/ci.yml):
#   swift test --enable-code-coverage
#   xcrun llvm-cov export -summary-only \
#     .build/debug/TamgaPackageTests.xctest/Contents/MacOS/TamgaPackageTests \
#     -instr-profile .build/debug/codecov/default.profdata \
#     | Scripts/check-coverage.sh
#
# Reads the `llvm-cov export -summary-only` JSON summary from stdin, extracts
# the overall line-coverage percentage, and fails (non-zero exit) if it is
# below THRESHOLD.
#
# Requires: python3 (for JSON parsing -- avoids a jq dependency in the
# runner image) or jq if present; falls back to python3.

set -eu

THRESHOLD=80

INPUT="$(cat)"

if [ -z "$INPUT" ]; then
  echo "check-coverage.sh: no input received on stdin (expected llvm-cov JSON summary)" >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  PERCENT=$(printf '%s' "$INPUT" | jq -r '.data[0].totals.lines.percent')
elif command -v python3 >/dev/null 2>&1; then
  PERCENT=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(data["data"][0]["totals"]["lines"]["percent"])
')
else
  echo "check-coverage.sh: neither jq nor python3 is available to parse coverage JSON" >&2
  exit 1
fi

PERCENT_INT=$(printf '%.0f' "$PERCENT")

echo "check-coverage.sh: line coverage is ${PERCENT}% (threshold: ${THRESHOLD}%)"

if [ "$PERCENT_INT" -lt "$THRESHOLD" ]; then
  echo "check-coverage.sh: FAIL -- coverage ${PERCENT}% is below the ${THRESHOLD}% gate" >&2
  exit 1
fi

echo "check-coverage.sh: PASS"
