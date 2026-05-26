#!/usr/bin/env bash
#
# CI check: ensure generated contract files are up to date with the schema.
#
# Run this in CI after every commit. It regenerates the artifacts and
# fails the build if they differ from what's committed — preventing
# stale generated files from sneaking in.
#
# Usage:  ./scripts/check_contracts.sh
# Exits 0 if clean, 1 if generated files are out of date.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Checking contract artifacts are up to date"

# Snapshot current files
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

cp shared/contracts/sailor_models.py "$TMPDIR/sailor_models.py.committed"
cp shared/contracts/sailor.types.ts  "$TMPDIR/sailor.types.ts.committed"

# Regenerate
./scripts/regen_contracts.sh > /dev/null

# Diff
FAIL=0

if ! diff -q "$TMPDIR/sailor_models.py.committed" shared/contracts/sailor_models.py > /dev/null; then
  echo "FAIL: shared/contracts/sailor_models.py is out of date."
  echo "      Run ./scripts/regen_contracts.sh and commit the result."
  diff -u "$TMPDIR/sailor_models.py.committed" shared/contracts/sailor_models.py | head -40
  FAIL=1
fi

if ! diff -q "$TMPDIR/sailor.types.ts.committed" shared/contracts/sailor.types.ts > /dev/null; then
  echo "FAIL: shared/contracts/sailor.types.ts is out of date."
  echo "      Run ./scripts/regen_contracts.sh and commit the result."
  diff -u "$TMPDIR/sailor.types.ts.committed" shared/contracts/sailor.types.ts | head -40
  FAIL=1
fi

if [ $FAIL -eq 0 ]; then
  echo "OK: contract artifacts are in sync with the schema."
fi

# Also run the SSE contract drift check if sse_contract.md exists
SSE_DOC_PATHS=(
  "$REPO_ROOT/spec/sse_contract.md"
  "$REPO_ROOT/sse_contract.md"
)
SSE_DOC=""
for p in "${SSE_DOC_PATHS[@]}"; do
  if [ -f "$p" ]; then SSE_DOC="$p"; break; fi
done

if [ -n "$SSE_DOC" ]; then
  echo ""
  if ! python3 "$REPO_ROOT/scripts/check_sse_contract.py"; then
    FAIL=1
  fi
fi

exit $FAIL
