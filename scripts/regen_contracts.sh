#!/usr/bin/env bash
#
# Regenerate all contract artifacts from sailor.schema.json.
#
# This script must be run after ANY edit to sailor.schema.json.
# CI should run this and diff against the committed files to detect
# stale generated code.
#
# Usage:
#   ./scripts/regen_contracts.sh
#
# Required tools:
#   python3, pip3 (Python 3.11+)
#   node, npm (Node 18+)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA="$REPO_ROOT/shared/contracts/sailor.schema.json"
PY_OUT="$REPO_ROOT/shared/contracts/sailor_models.py"
TS_OUT="$REPO_ROOT/shared/contracts/sailor.types.ts"

if [ ! -f "$SCHEMA" ]; then
  echo "FATAL: $SCHEMA not found" >&2
  exit 1
fi

echo "==> Validating JSON Schema syntax"
python3 - <<PYEOF
import json, sys
from jsonschema import Draft202012Validator
with open("$SCHEMA") as f:
    schema = json.load(f)
Draft202012Validator.check_schema(schema)
print(f"   OK: {len(schema['\$defs'])} definitions")
PYEOF

echo "==> Generating Pydantic models -> $PY_OUT"
datamodel-codegen \
  --input "$SCHEMA" \
  --input-file-type jsonschema \
  --output "$PY_OUT" \
  --output-model-type pydantic_v2.BaseModel \
  --target-python-version 3.11 \
  --use-schema-description \
  --use-field-description \
  --use-double-quotes \
  --use-union-operator \
  --use-standard-collections \
  --collapse-root-models \
  --field-constraints \
  --enum-field-as-literal one \
  --disable-timestamp \
  --custom-file-header "# AUTO-GENERATED from sailor.schema.json. DO NOT EDIT.
# Run scripts/regen_contracts.sh to regenerate."

echo "==> Generating TypeScript types -> $TS_OUT"
cd "$REPO_ROOT"
node scripts/gen_ts.mjs

echo "==> Validating TypeScript compiles"
npx tsc --noEmit

echo "==> Validating Pydantic models import"
python3 -c "
import sys
sys.path.insert(0, '$REPO_ROOT/shared/contracts')
import sailor_models
print(f'   OK: {len([n for n in dir(sailor_models) if not n.startswith(\"_\")])} symbols')
"

echo "==> Regenerating SSE example fixtures"
python3 "$REPO_ROOT/scripts/gen_sse_examples.py"

echo ""
echo "Contract regeneration complete."
echo "If you see diffs in $PY_OUT or $TS_OUT, commit them along with the schema change."
echo "If the SSE examples changed, also update sse_contract.md (the doc embeds them inline)."
echo "Run scripts/check_sse_contract.py to verify the doc and the fixtures agree."
