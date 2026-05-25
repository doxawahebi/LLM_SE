#!/usr/bin/env python3
"""
Verify that sse_contract.md's embedded JSON examples match the
auto-generated reference examples in shared/contracts/examples/sse/.

Run this in CI alongside scripts/check_contracts.sh. If it fails, either:
  - sse_contract.md was hand-edited and drifted from the schema → fix the doc, or
  - the schema changed → regenerate examples and update the doc

Exits 0 if clean, 1 if drift detected.
"""
from __future__ import annotations

import datetime as dt
import difflib
import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "spec" / "sse_contract.md"            # adjust to your repo layout
ALT_DOC = REPO_ROOT / "sse_contract.md"                  # fallback if at repo root
EXAMPLES_DIR = REPO_ROOT / "shared" / "contracts" / "examples" / "sse"


def normalize_timestamps(obj):
    """Normalize ISO timestamps to second precision so .000Z vs Z don't trip the diff."""
    if isinstance(obj, dict):
        return {k: normalize_timestamps(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_timestamps(x) for x in obj]
    if isinstance(obj, str):
        try:
            t = dt.datetime.fromisoformat(obj.replace("Z", "+00:00"))
            return t.replace(microsecond=0, tzinfo=dt.timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )
        except (ValueError, AttributeError):
            return obj
    return obj


def main() -> int:
    if DOC.exists():
        doc_path = DOC
    elif ALT_DOC.exists():
        doc_path = ALT_DOC
    else:
        print(f"FATAL: neither {DOC} nor {ALT_DOC} exists", file=sys.stderr)
        return 1

    if not EXAMPLES_DIR.is_dir():
        print(f"FATAL: {EXAMPLES_DIR} not found", file=sys.stderr)
        return 1

    print(f"==> Verifying {doc_path} against {EXAMPLES_DIR}")
    doc_text = doc_path.read_text()
    blocks = re.findall(r"```json\n(.*?)\n```", doc_text, re.DOTALL)

    issues = 0
    matched = 0
    seen_kinds: set[str] = set()

    for i, block in enumerate(blocks):
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError as e:
            print(f"  Block {i}: INVALID JSON — {e}")
            issues += 1
            continue

        # The contract embeds a few non-kind examples (ApiError, error responses).
        # Skip anything that isn't a kind-bearing SSEMessage.
        if "kind" not in parsed:
            continue

        kind = parsed["kind"]
        seen_kinds.add(kind)
        expected_file = EXAMPLES_DIR / f"{kind}.json"
        if not expected_file.exists():
            print(f"  Block {i} (kind={kind}): no matching example file at {expected_file}")
            issues += 1
            continue

        expected = json.loads(expected_file.read_text())
        norm_actual = normalize_timestamps(parsed)
        norm_expected = normalize_timestamps(expected)
        if norm_actual != norm_expected:
            print(f"  Block {i} (kind={kind}): DRIFT from {expected_file.name}")
            a = json.dumps(norm_actual, indent=2, sort_keys=True).splitlines()
            b = json.dumps(norm_expected, indent=2, sort_keys=True).splitlines()
            for line in list(difflib.unified_diff(a, b, lineterm="", n=2))[:30]:
                print(f"      {line}")
            issues += 1
        else:
            matched += 1

    # Also verify every example file has a corresponding doc block,
    # so newly added kinds can't be silently un-documented.
    all_example_kinds = {f.stem for f in EXAMPLES_DIR.glob("*.json") if f.stem != "batch"}
    missing_from_doc = all_example_kinds - seen_kinds
    if missing_from_doc:
        print(f"  Kinds with example files but not documented in {doc_path.name}:")
        for k in sorted(missing_from_doc):
            print(f"      - {k}")
        issues += len(missing_from_doc)

    print()
    print(f"  Matched: {matched}")
    print(f"  Issues:  {issues}")
    return 0 if issues == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
