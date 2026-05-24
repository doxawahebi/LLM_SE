# CLAUDE_e2e_test.md — E2E Pipeline Test Implementation

> Claude Code reads this file when implementing or updating the E2E
> test suite.
> Spec reference: spec/e2e_test_spec.md (source of truth for contracts).
> All Absolute Rules in CLAUDE.md apply.
> Never re-implement pipeline logic — import from sailor/ package.

---

## Integration with Existing Files

```
Read these before implementing:
  spec/e2e_test_spec.md        ← what to build (contracts, schemas)
  design/CLAUDE_infra.md       ← DockerRunner API
  design/CLAUDE_phase2.md      ← LLM provider strategy (Gemini/Claude)
  paper/paper_overview.md      ← assertion templates per CWE

Replace these (legacy):
  tests/e2e_self_test.py       ← rewrite from scratch
  tests/e2e_workspace/         ← rewrite all workspaces
```

---

## Target File Structure to Create

```
tests/
├── e2e_self_test.py             ← test runner (rewrite)
├── conftest.py                  ← pytest fixtures
└── e2e_workspace/
    ├── cwe_122/                 ← heap buffer overflow (implement first)
    │   ├── target.c
    │   ├── Makefile
    │   ├── expected.json
    │   ├── README.md
    │   └── fixtures/
    │       ├── spec.json
    │       ├── witness.ktest
    │       ├── verified_bug.json
    │       └── mock_llm_turns/
    │           ├── 00.json
    │           ├── 01.json
    │           └── ...
    ├── cwe_121/                 ← stack buffer overflow
    ├── cwe_416/                 ← use-after-free
    └── cwe_476/                 ← null dereference
```

---

## Phase A — Workspace Files

Implement workspace files for all four required CWEs.
Use the exact templates from spec/e2e_test_spec.md §5.
Do NOT deviate from the template — fixture generation depends on
function names, argument order, and line numbers being stable.

### A1. cwe_122 (implement first — used for all validation)

**target.c** — copy exactly from spec §5.1:
```c
#include <stdlib.h>
#include <string.h>

static void vulnerable(unsigned char *dst, size_t dst_size,
                        unsigned char *src, size_t src_size) {
    memcpy(dst, src, src_size);   /* ← ℓ */
}

int main(void) {
    unsigned char *dst = malloc(16);
    unsigned char *src = malloc(512);
    size_t n = 17;
    vulnerable(dst, 16, src, n);
    free(dst);
    free(src);
    return 0;
}
```

**Makefile:**
```makefile
CC      = clang
CFLAGS  = -O1 -g
TARGET  = target

all: $(TARGET)

$(TARGET): target.c
	$(CC) $(CFLAGS) target.c -o $(TARGET)

clean:
	rm -f $(TARGET)

# compile_commands.json for CodeQL (bear required)
cdb:
	bear -- $(MAKE) all
```

**expected.json** — copy schema from spec §6, fill values:
```json
{
  "id": "E2E-CWE-122",
  "cwe": "CWE-122",
  "description": "Heap-based buffer overflow via unchecked memcpy size",
  "target": {
    "file": "target.c",
    "func": "vulnerable",
    "line": 6
  },
  "phase1": {
    "must_detect": true,
    "expected_rule_id": "local/cpp/cwe-120-overflow",
    "expected_assertion_template": "n <= min(len(dst), len(src))",
    "min_findings": 1
  },
  "phase2": {
    "expected_outcome": "bug_triggered",
    "max_turns": 20,
    "witness_symbolic_vars": ["src_size"],
    "witness_must_violate": "src_size > 16"
  },
  "phase3": {
    "expected_verdict": "CONFIRMED",
    "expected_asan_type": "heap-buffer-overflow",
    "crash_must_be_in_file": "target.c"
  },
  "performance": {
    "max_wall_seconds": 120,
    "max_llm_tokens": 50000,
    "max_klee_paths": 500
  }
}
```

**README.md:**
```markdown
# CWE-122: Heap-Based Buffer Overflow

## Vulnerability

`vulnerable()` calls `memcpy(dst, src, src_size)` without checking
that `src_size <= dst_size`. When `src_size = 17` and `dst` is only
16 bytes, the copy writes 1 byte past the end of the heap allocation.

## Detection

- **Phase 1**: CodeQL query `local/cpp/cwe-120-overflow` flags the
  `memcpy` call because `src_size` is not guarded by `sizeof` or `strlen`.
- **Phase 2**: KLEE finds `src_size = 17` satisfies `src_size > 16`
  and triggers an out-of-bounds write.
- **Phase 3**: ASan confirms `heap-buffer-overflow` in `target.c`.

## Entry point

`vulnerable()` — called directly from `main()`, no guard conditions.
```

### A2. cwe_121 — copy from spec §5.2

### A3. cwe_416 — copy from spec §5.3
Note: free() stub in Phase 2 code slice MUST call real free().
Verify this in expected.json comment and README.

### A4. cwe_476 — copy from spec §5.4

---

## Phase B — Test Runner

Implement `tests/e2e_self_test.py` and `tests/conftest.py`.

### B1. conftest.py

```python
import pytest
import json
from pathlib import Path
from sailor.infra.docker_runner import DockerRunner, RunnerConfig

WORKSPACE_ROOT = Path(__file__).parent / "e2e_workspace"

def pytest_configure(config):
    config.addinivalue_line("markers", "e2e_full: full pipeline test")
    config.addinivalue_line("markers", "e2e_phase1: Phase 1 only")
    config.addinivalue_line("markers", "e2e_phase2: Phase 2 only")
    config.addinivalue_line("markers", "e2e_phase3: Phase 3 only")

@pytest.fixture(params=["cwe_122", "cwe_121", "cwe_416", "cwe_476"])
def workspace(request):
    """Yields (workspace_path, expected) for each CWE directory."""
    path = WORKSPACE_ROOT / request.param
    expected = json.loads((path / "expected.json").read_text())
    return path, expected

@pytest.fixture
def cwe_122_workspace():
    """Single workspace fixture for validation tests."""
    path = WORKSPACE_ROOT / "cwe_122"
    expected = json.loads((path / "expected.json").read_text())
    return path, expected

@pytest.fixture
def docker_runner(workspace):
    """DockerRunner for one test workspace. Always stopped in teardown."""
    path, _ = workspace
    runner = DockerRunner(
        cve_id=f"e2e-{path.name}",
        config=RunnerConfig(
            image="sailor-runner:latest",
            workspace_base=Path("/tmp/e2e_workspace"),
            output_base=Path("/tmp/e2e_output"),
        ),
    )
    runner.start()
    yield runner
    runner.stop()   # always called even on test failure
```

### B2. e2e_self_test.py — class structure

```python
import os
import json
import time
import pytest
from pathlib import Path

from sailor.phase1.pipeline import Phase1Pipeline, Phase1Config
from sailor.phase2.pipeline import Phase2Pipeline, Phase2Config
from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config
from sailor.models.schemas import SEOutcome, ValidationVerdict
from sailor.infra.docker_runner import DockerRunner


# ── Helpers ────────────────────────────────────────────────────────

def load_expected(workspace: Path) -> dict:
    return json.loads((workspace / "expected.json").read_text())

def load_fixture(workspace: Path, name: str) -> Path:
    path = workspace / "fixtures" / name
    if not path.exists():
        pytest.skip(f"fixture not found: {path} — run fixture generation first")
    return path

def assert_phase1(result, expected: dict, workspace: Path) -> None:
    """Assert Phase 1 output matches expected.json phase1 section."""
    p1 = expected["phase1"]
    tgt = expected["target"]

    if p1["must_detect"]:
        matching = [
            s for s in result.specifications
            if tgt["file"] in s.file
            and tgt["func"] in s.func
        ]
        assert matching, (
            f"Phase 1 did not detect {tgt['func']} in {tgt['file']}.\n"
            f"All specs found: {[s.file for s in result.specifications]}"
        )
        spec = matching[0]
        assert p1["expected_rule_id"] in spec.rule_id, (
            f"Expected rule_id {p1['expected_rule_id']}, got {spec.rule_id}"
        )
        assert spec.assertion_template == p1["expected_assertion_template"], (
            f"Expected template {p1['expected_assertion_template']!r}, "
            f"got {spec.assertion_template!r}"
        )
    assert len(result.specifications) >= p1["min_findings"]

def assert_phase2(results, expected: dict) -> None:
    """Assert Phase 2 output matches expected.json phase2 section."""
    p2 = expected["phase2"]
    triggered = [r for r in results if r.outcome == SEOutcome.BUG_TRIGGERED]
    assert triggered, (
        f"Phase 2 did not trigger a bug. "
        f"Outcomes: {[r.outcome for r in results]}"
    )
    r = triggered[0]
    assert r.turns_used <= p2["max_turns"], (
        f"Phase 2 used {r.turns_used} turns, max allowed {p2['max_turns']}"
    )
    if r.witness:
        for var in p2["witness_symbolic_vars"]:
            assert any(var in kp for kp in r.witness.ktest_paths), (
                f"Witness does not contain symbolic var '{var}'"
            )

def assert_phase3(p3_result, expected: dict) -> None:
    """Assert Phase 3 output matches expected.json phase3 section."""
    p3 = expected["phase3"]
    confirmed = [
        r for r in p3_result.results
        if r.verdict == ValidationVerdict.CONFIRMED
    ]
    assert confirmed, (
        f"Phase 3 did not confirm the bug. "
        f"Verdicts: {[r.verdict for r in p3_result.results]}"
    )
    r = confirmed[0]
    assert r.asan_type == p3["expected_asan_type"], (
        f"Expected ASan type {p3['expected_asan_type']!r}, got {r.asan_type!r}"
    )
    assert p3["crash_must_be_in_file"] in r.file, (
        f"Crash in {r.file!r}, expected file containing "
        f"{p3['crash_must_be_in_file']!r}"
    )


# ── Phase 1 only ───────────────────────────────────────────────────

@pytest.mark.e2e_phase1
def test_phase1_detects_vulnerability(workspace, docker_runner, tmp_path):
    """
    Phase 1 must detect the vulnerability at the location defined
    in expected.json. No LLM calls. Fast.
    """
    ws, expected = workspace
    runner = docker_runner

    # Setup target inside container
    runner.setup_target(
        project_url=None,           # local workspace, not a git repo
        commit=None,
        build_commands=["bear -- make all"],
        dependencies=["build-essential", "bear", "clang"],
        local_source_path=str(ws), # copy workspace into container
    )

    config = Phase1Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase1",
        build_command="bear -- make all",
    )
    result = Phase1Pipeline(config).run()

    assert_phase1(result, expected, ws)

    # Write fixture for downstream tests
    fixture_dir = ws / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    if result.specifications:
        tgt = expected["target"]
        spec = next(
            s for s in result.specifications
            if tgt["func"] in s.func
        )
        (fixture_dir / "spec.json").write_text(spec.model_dump_json(indent=2))


# ── Phase 2 only ───────────────────────────────────────────────────

@pytest.mark.e2e_phase2
def test_phase2_triggers_bug(workspace, docker_runner, tmp_path):
    """
    Phase 2 must trigger a bug within max_turns.
    Uses fixtures/spec.json; skips if fixture missing.
    Uses Gemini Flash by default; mock LLM if E2E_MOCK_LLM=true.
    """
    ws, expected = workspace
    spec_path = load_fixture(ws, "spec.json")

    from sailor.models.schemas import VulnerabilitySpec
    spec = VulnerabilitySpec.model_validate_json(spec_path.read_text())

    config = Phase2Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase2",
        docker_runner=docker_runner,
        T_max=expected["phase2"]["max_turns"],  # cap for e2e speed
        # LLMClient resolved from env (Gemini default, Claude if flag set)
        # MockLLMClient used if E2E_MOCK_LLM=true (see _resolve_llm_client)
    )
    results = Phase2Pipeline(config).run([spec])

    assert_phase2(results, expected)

    # Write fixture
    fixture_dir = ws / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    triggered = next(r for r in results if r.outcome == SEOutcome.BUG_TRIGGERED)
    if triggered.witness and triggered.witness.ktest_paths:
        import shutil
        shutil.copy(
            triggered.witness.ktest_paths[0],
            fixture_dir / "witness.ktest",
        )


# ── Phase 3 only ───────────────────────────────────────────────────

@pytest.mark.e2e_phase3
def test_phase3_confirms_vulnerability(workspace, docker_runner, tmp_path):
    """
    Phase 3 must confirm the vulnerability with ASan.
    Uses fixtures/witness.ktest; skips if fixture missing.
    No LLM calls. Fast.
    """
    ws, expected = workspace
    spec_path   = load_fixture(ws, "spec.json")
    witness_path = load_fixture(ws, "witness.ktest")

    from sailor.models.schemas import VulnerabilitySpec, WitnessInput, SEOutcome
    spec = VulnerabilitySpec.model_validate_json(spec_path.read_text())

    witness = WitnessInput(
        spec_id=spec.rule_id,
        ktest_paths=[str(witness_path)],
        outcome=SEOutcome.BUG_TRIGGERED,
        harness=None,
        turns_used=0,
        refine_count=0,
    )

    config = Phase3Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase3",
        docker_runner=docker_runner,
    )
    p3_result = Phase3Pipeline(config).run([witness], [spec])

    assert_phase3(p3_result, expected)

    # Write fixture
    fixture_dir = ws / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    confirmed = next(
        r for r in p3_result.results
        if r.verdict == ValidationVerdict.CONFIRMED
    )
    (fixture_dir / "verified_bug.json").write_text(
        json.dumps(json.loads(confirmed.model_dump_json()), indent=2)
    )


# ── Full pipeline ──────────────────────────────────────────────────

@pytest.mark.e2e_full
def test_full_pipeline(workspace, docker_runner, tmp_path):
    """
    Full Phase 1 → 2 → 3 pipeline.
    Runs real LLM (Gemini Flash by default).
    Validates all three phases against expected.json.
    """
    ws, expected = workspace
    start = time.perf_counter()

    # Phase 1
    p1_config = Phase1Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase1",
        build_command="bear -- make all",
    )
    p1_result = Phase1Pipeline(p1_config).run()
    assert_phase1(p1_result, expected, ws)

    # Phase 2 — use only the spec matching the target
    tgt = expected["target"]
    target_specs = [
        s for s in p1_result.specifications
        if tgt["func"] in s.func
    ]
    assert target_specs, "Phase 1 found no spec for target function"

    p2_config = Phase2Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase2",
        docker_runner=docker_runner,
        T_max=expected["phase2"]["max_turns"],
    )
    p2_results = Phase2Pipeline(p2_config).run(target_specs)
    assert_phase2(p2_results, expected)

    # Phase 3
    triggered = [r for r in p2_results if r.outcome == SEOutcome.BUG_TRIGGERED]
    p3_config = Phase3Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase3",
        docker_runner=docker_runner,
    )
    p3_result = Phase3Pipeline(p3_config).run(triggered, target_specs)
    assert_phase3(p3_result, expected)

    # Performance check (warn only, do not fail)
    elapsed = time.perf_counter() - start
    perf = expected["performance"]
    if elapsed > perf["max_wall_seconds"]:
        pytest.warning(
            f"Performance: {elapsed:.1f}s > limit {perf['max_wall_seconds']}s"
        )
```

### B3. Mock LLM Client

```python
# sailor/phase2/mock_llm_client.py

import os
import json
import hashlib
from pathlib import Path


class MockLLMError(Exception):
    """Raised when mock cannot match a recorded response."""


class MockLLMClient:
    """
    Test-only LLM client that replays pre-recorded responses.
    Activated by E2E_MOCK_LLM=true environment variable.
    Recording mode activated by E2E_MOCK_LLM=record.

    Response files: fixtures/mock_llm_turns/<turn_number>.json
    Each file: { "prompt_hash": str, "response": str }

    prompt_hash = sha256 of the full prompt text (first 2000 chars).
    If hash matches → return recorded response.
    If hash mismatches → raise MockLLMError with diff hint.
    """

    def __init__(self, fixture_dir: Path):
        self.fixture_dir = fixture_dir / "mock_llm_turns"
        self.turn = 0
        self.mode = os.environ.get("E2E_MOCK_LLM", "").lower()
        # mode: "true" → playback, "record" → record

    def chat(
        self,
        messages: list[dict],
        system_prompt: str = "",
        max_tokens: int = 8192,
    ) -> str:
        prompt_text = system_prompt + str(messages)
        prompt_hash = hashlib.sha256(
            prompt_text[:2000].encode()
        ).hexdigest()[:16]

        if self.mode == "record":
            return self._record(prompt_hash, messages, system_prompt)
        else:
            return self._playback(prompt_hash)

    def _playback(self, prompt_hash: str) -> str:
        path = self.fixture_dir / f"{self.turn:02d}.json"
        if not path.exists():
            raise MockLLMError(
                f"No mock response for turn {self.turn} at {path}. "
                f"Run with E2E_MOCK_LLM=record to generate."
            )
        recorded = json.loads(path.read_text())
        if recorded["prompt_hash"] != prompt_hash:
            raise MockLLMError(
                f"Turn {self.turn}: prompt hash mismatch.\n"
                f"  recorded: {recorded['prompt_hash']}\n"
                f"  current:  {prompt_hash}\n"
                f"Prompts changed — re-record with E2E_MOCK_LLM=record."
            )
        self.turn += 1
        return recorded["response"]

    def _record(self, prompt_hash: str, messages, system_prompt) -> str:
        # In record mode, call the real LLM and save the response
        from sailor.infra.celery_tasks import LLMClientFactory
        real_client = LLMClientFactory.from_env()
        response = real_client.chat(messages, system_prompt)

        self.fixture_dir.mkdir(parents=True, exist_ok=True)
        path = self.fixture_dir / f"{self.turn:02d}.json"
        path.write_text(json.dumps({
            "prompt_hash": prompt_hash,
            "response": response,
        }, indent=2))
        self.turn += 1
        return response


def resolve_llm_client(fixture_dir: Path):
    """
    Return MockLLMClient if E2E_MOCK_LLM is set, otherwise
    return the real LLMClient from LLMClientFactory.from_env().
    Called by Phase2Config construction in test context.
    """
    mock_mode = os.environ.get("E2E_MOCK_LLM", "").lower()
    if mock_mode in ("true", "record"):
        return MockLLMClient(fixture_dir)
    from sailor.infra.celery_tasks import LLMClientFactory
    return LLMClientFactory.from_env()
```

---

## Phase C — DockerRunner Local Source Support

The current DockerRunner only supports `git clone` targets.
E2E tests use local workspace directories.
Add this method to `sailor/infra/docker_runner.py`:

```python
def copy_local_source(self, local_path: str) -> str:
    """
    Copy a local directory into the container's workspace.
    Used by e2e tests where the target is a local C file,
    not a git repository.

    Returns the path inside the container.
    """
    container_path = f"/workspace/{self.cve_id}/src"
    self.exec(f"mkdir -p {container_path}")

    # docker cp from host into container
    result = self._local_run([
        "docker", "cp",
        f"{local_path}/.",
        f"{self.container_id}:{container_path}",
    ])
    if result.returncode != 0:
        raise RuntimeError(
            f"docker cp failed: {result.stderr}"
        )
    return container_path
```

Also add `local_source_path` parameter to `setup_target()`:

```python
def setup_target(
    self,
    project_url: str | None,
    commit: str | None,
    build_commands: list[str],
    dependencies: list[str],
    local_source_path: str | None = None,  # NEW
) -> Path:
    """
    If local_source_path is provided: copy local directory into container.
    If project_url is provided: git clone + checkout.
    Exactly one of the two must be set.
    """
    if local_source_path and project_url:
        raise ValueError("Provide local_source_path OR project_url, not both.")
    if not local_source_path and not project_url:
        raise ValueError("Provide either local_source_path or project_url.")

    if dependencies:
        self.exec(
            f"apt-get update -qq && apt-get install -y "
            f"--no-install-recommends {' '.join(dependencies)}",
            timeout=300,
        )

    if local_source_path:
        project_dir = self.copy_local_source(local_source_path)
    else:
        project_dir = f"/workspace/{self.cve_id}/src"
        self.exec(f"git clone --depth=50 {project_url} {project_dir}")
        self.exec(f"git -C {project_dir} checkout {commit}")

    for cmd in build_commands:
        self.exec(cmd, cwd=project_dir, timeout=self.config.build_timeout)

    return Path(project_dir)
```

---

## Phase D — Fixture Generation Script

Create `tests/generate_fixtures.py` for one-time fixture generation:

```python
#!/usr/bin/env python3
"""
Generate fixtures for all e2e workspaces.
Must be run once before E2E_MOCK_LLM=true tests can run.

Usage:
  # Generate all fixtures (requires real LLM + Docker)
  E2E_MOCK_LLM=record python tests/generate_fixtures.py

  # Generate fixtures for one workspace only
  E2E_MOCK_LLM=record python tests/generate_fixtures.py --workspace cwe_122

After running, commit the generated fixtures/ directories.
"""

import argparse
import subprocess
import sys

WORKSPACES = ["cwe_122", "cwe_121", "cwe_416", "cwe_476"]

def generate(workspace: str) -> bool:
    print(f"\n=== Generating fixtures for {workspace} ===")

    # Phase 1
    result = subprocess.run([
        "pytest", "tests/e2e_self_test.py",
        "-m", "e2e_phase1", "-k", workspace,
        "-v", "--no-header",
    ], env={**__import__("os").environ})
    if result.returncode != 0:
        print(f"FAILED: Phase 1 for {workspace}")
        return False

    # Phase 2 (record mode)
    result = subprocess.run([
        "pytest", "tests/e2e_self_test.py",
        "-m", "e2e_phase2", "-k", workspace,
        "-v", "--no-header",
    ], env={**__import__("os").environ, "E2E_MOCK_LLM": "record"})
    if result.returncode != 0:
        print(f"FAILED: Phase 2 for {workspace}")
        return False

    # Phase 3
    result = subprocess.run([
        "pytest", "tests/e2e_self_test.py",
        "-m", "e2e_phase3", "-k", workspace,
        "-v", "--no-header",
    ])
    if result.returncode != 0:
        print(f"FAILED: Phase 3 for {workspace}")
        return False

    print(f"OK: fixtures generated for {workspace}")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", choices=WORKSPACES)
    args = parser.parse_args()

    targets = [args.workspace] if args.workspace else WORKSPACES
    failed = [w for w in targets if not generate(w)]

    if failed:
        print(f"\nFailed: {failed}")
        sys.exit(1)
    print(f"\nAll fixtures generated successfully.")
```

---

## Implementation Order

```
Step 1. Create workspace files (Phase A).
        → cwe_122/ first: target.c, Makefile, expected.json, README.md
        → Verify: clang -O1 -g target.c -o target && ./target
        → Verify: bear -- make all generates compile_commands.json
        → Then cwe_121/, cwe_416/, cwe_476/

Step 2. Add DockerRunner.copy_local_source() (Phase C).
        → Add method to sailor/infra/docker_runner.py
        → Add local_source_path param to setup_target()
        → Unit test: verify docker cp works correctly

Step 3. Add MockLLMClient (Phase B3).
        → Create sailor/phase2/mock_llm_client.py
        → Unit test MockLLMClient playback and record modes
        → Unit test hash mismatch raises MockLLMError

Step 4. Implement test runner (Phase B1 + B2).
        → conftest.py: workspace and docker_runner fixtures
        → e2e_self_test.py: all four test functions
        → assert_phase1/2/3 helpers

Step 5. Run Phase 1 tests (no LLM required).
        → pytest tests/e2e_self_test.py -m e2e_phase1 -v
        → All four workspaces must PASS.
        → fixtures/spec.json generated for each workspace.

Step 6. Generate mock LLM fixtures for Phase 2.
        → Requires: GEMINI_API_KEY set, Docker running
        → E2E_MOCK_LLM=record python tests/generate_fixtures.py
        → Commit generated fixtures/mock_llm_turns/ directories.

Step 7. Run Phase 2 mock tests.
        → E2E_MOCK_LLM=true pytest tests/e2e_self_test.py -m e2e_phase2 -v
        → All four workspaces must PASS.
        → fixtures/witness.ktest generated for each workspace.

Step 8. Run Phase 3 tests (no LLM required).
        → pytest tests/e2e_self_test.py -m e2e_phase3 -v
        → All four workspaces must PASS.
        → fixtures/verified_bug.json generated for each workspace.

Step 9. Run full pipeline on cwe_122 only (real LLM).
        → pytest tests/e2e_self_test.py -m e2e_full -k cwe_122 -v
        → Must PASS within 120 seconds.

Step 10. Update CLAUDE_Sessions_prompt.md Session 2~4.
         → Each session's validation step now references e2e tests:
           "pytest tests/e2e_self_test.py -m e2e_phaseN -v"
```

---

## Validation Checklist

```
After implementation, verify ALL items:

Workspace files:
  □ clang -O1 -g target.c -o target succeeds for all 4 workspaces
  □ bear -- make all generates compile_commands.json for all 4
  □ expected.json parses as valid JSON for all 4
  □ target.func exists in target.c at target.line

DockerRunner extension:
  □ copy_local_source() copies files into container correctly
  □ setup_target() with local_source_path works without git
  □ setup_target() raises ValueError if both or neither source given

MockLLMClient:
  □ Playback returns recorded response when hash matches
  □ Playback raises MockLLMError when hash mismatches
  □ Record mode saves responses to fixtures/mock_llm_turns/
  □ resolve_llm_client() returns MockLLMClient when E2E_MOCK_LLM=true

Test runner:
  □ pytest -m e2e_phase1 passes for all 4 workspaces
  □ pytest -m e2e_phase2 passes (mock mode) for all 4 workspaces
  □ pytest -m e2e_phase3 passes for all 4 workspaces
  □ pytest -m e2e_full -k cwe_122 passes within 120s
  □ Fixture files written to workspace fixtures/ after each phase test
```
