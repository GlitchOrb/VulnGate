#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

BIN="./bin/vulngate"
DB="./.tmp/vulngate-real-vuln.db"
OUT="./.tmp/real-vuln-results.sarif"
TARGET="./examples/repos/real-vuln-npm-lodash"
OSV_DIR="./examples/vulndb/osv-real"
GO_BIN="${GO_BIN:-}"

if [ -z "$GO_BIN" ]; then
  if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
  elif [ -x /tmp/vg-go/go/bin/go ]; then
    GO_BIN="/tmp/vg-go/go/bin/go"
  else
    echo "go toolchain not found. install Go or set GO_BIN=/path/to/go"
    exit 2
  fi
fi

mkdir -p ./bin ./.tmp

"$GO_BIN" build -o "$BIN" ./cmd/vulngate
"$BIN" db init --db "$DB"
"$BIN" db import --db "$DB" --source "$OSV_DIR"

set +e
"$BIN" scan --db "$DB" "$TARGET" > "$OUT"
SCAN_EXIT=$?
set -e

echo "scan exit code: $SCAN_EXIT"
echo "sarif: $OUT"

if grep -q 'GHSA-35jh-r3h4-6jhm' "$OUT"; then
  echo "detected real vulnerability GHSA-35jh-r3h4-6jhm"
else
  echo "expected vulnerability not found in SARIF"
  exit 1
fi

if [ "$SCAN_EXIT" -eq 1 ]; then
  echo "policy gate failed as expected (high reachable vulnerability)"
elif [ "$SCAN_EXIT" -eq 0 ]; then
  echo "scan passed policy; check policy config if failure was expected"
else
  echo "tool error during scan"
  exit "$SCAN_EXIT"
fi
