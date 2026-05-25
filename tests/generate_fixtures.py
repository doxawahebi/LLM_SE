#!/usr/bin/env python3
"""Generate fixtures for all e2e workspaces.

Must be run once before E2E_MOCK_LLM=true tests can run.

Usage:
  # Generate all fixtures (requires ANTHROPIC_API_KEY + Docker)
  E2E_MOCK_LLM=record python tests/generate_fixtures.py

  # Generate fixtures for one workspace only
  E2E_MOCK_LLM=record python tests/generate_fixtures.py --workspace cwe_122

After running, commit the generated fixtures/ directories.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

WORKSPACES = ["cwe_122", "cwe_121", "cwe_416", "cwe_476"]


def run_pytest(mark: str, workspace: str, extra_env: dict | None = None) -> bool:
    env = {**os.environ, **(extra_env or {})}
    result = subprocess.run(
        [
            "pytest", "tests/e2e_self_test.py",
            "-m", mark,
            "-k", workspace,
            "-v", "--no-header",
        ],
        env=env,
    )
    return result.returncode == 0


def generate(workspace: str) -> bool:
    print(f"\n=== Generating fixtures for {workspace} ===")

    if not run_pytest("e2e_phase1", workspace):
        print(f"FAILED: Phase 1 for {workspace}")
        return False

    if not run_pytest("e2e_phase2", workspace, {"E2E_MOCK_LLM": "record"}):
        print(f"FAILED: Phase 2 (record) for {workspace}")
        return False

    if not run_pytest("e2e_phase3", workspace):
        print(f"FAILED: Phase 3 for {workspace}")
        return False

    print(f"OK: fixtures generated for {workspace}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", choices=WORKSPACES, help="Single workspace to generate")
    args = parser.parse_args()

    targets = [args.workspace] if args.workspace else WORKSPACES
    failed = [w for w in targets if not generate(w)]

    if failed:
        print(f"\nFailed: {failed}")
        sys.exit(1)
    print("\nAll fixtures generated successfully.")
