"""E2E tests for the Sailor vulnerability discovery pipeline.

Markers
-------
e2e_phase1  Phase 1 only — uses pre-built SARIF fixtures, no Docker required.
e2e_phase2  Phase 2 only — requires Docker + (real LLM or E2E_MOCK_LLM=true).
e2e_phase3  Phase 3 only — requires Docker + fixtures/phase2_result.json.
e2e_full    Full Phase 1 → 2 → 3 pipeline — requires Docker + real LLM.

Run examples
------------
pytest tests/e2e_self_test.py -m e2e_phase1 -v
E2E_MOCK_LLM=true pytest tests/e2e_self_test.py -m e2e_phase2 -v
pytest tests/e2e_self_test.py -m e2e_phase3 -v
pytest tests/e2e_self_test.py -m e2e_full -k cwe_122 -v
"""

from __future__ import annotations

import datetime
import json
import shutil
import time
import warnings
from pathlib import Path

import pytest

from sailor.models.schemas import (
    Phase1Result,
    Phase2Result,
    SEOutcome,
    ValidationVerdict,
    VulnerabilitySpec,
)
from sailor.phase1.fact_enrichment import FactEnricher
from sailor.phase1.fact_generation import _parse_sarif
from sailor.phase1.spec_generation import SpecificationGenerator
from sailor.phase2.llm_orchestrator import Phase2Config
from sailor.phase2.mock_llm_client import resolve_llm_client
from sailor.phase2.pipeline import Phase2Pipeline
from sailor.phase3.pipeline import Phase3Config, Phase3Pipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_fixture(workspace: Path, name: str) -> Path:
    """Return the path to a fixture file, skipping the test if it is missing."""
    path = workspace / "fixtures" / name
    if not path.exists():
        pytest.skip(
            f"fixture not found: {path} — run tests/generate_fixtures.py first"
        )
    return path


def _phase1_from_sarif(ws: Path, src_copy: Path, out: Path) -> Phase1Result:
    """Run Phase 1 Stages 2+3 on the pre-built SARIF fixture.

    *src_copy* must be a copy of *ws* placed in a path that does NOT contain
    ``/tests/`` so that :data:`FILE_SKIP_PATTERNS` does not filter it out.
    """
    fixture_sarif = ws / "fixtures" / "findings.sarif"
    if not fixture_sarif.exists():
        pytest.skip(f"findings.sarif fixture not found: {fixture_sarif}")

    sarif_dict = json.loads(fixture_sarif.read_text(encoding="utf-8"))
    findings = _parse_sarif(sarif_dict, src_copy)

    enricher = FactEnricher(project_root=src_copy, output_dir=out)
    packs = enricher.run(findings)

    spec_gen = SpecificationGenerator(output_dir=out)
    specs = spec_gen.run(packs)

    return Phase1Result.build(
        project=f"e2e-{ws.name}",
        project_root=str(src_copy),
        total_findings=len(findings),
        specifications=specs,
        timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _normalize_spec(spec: VulnerabilitySpec, ws: Path, filename: str) -> VulnerabilitySpec:
    """Return *spec* with spec.file replaced by a stable workspace path.

    The stable path ``ws / filename`` is consistent across pytest runs so that
    Phase 2 prompt hashes remain identical between record and playback.
    """
    spec_dict = json.loads(spec.model_dump_json())
    spec_dict["file"] = str(ws / filename)
    return VulnerabilitySpec.model_validate(spec_dict)


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def assert_phase1(result: Phase1Result, expected: dict, ws: Path) -> None:
    """Assert Phase 1 output matches the expected.json phase1 section."""
    p1 = expected["phase1"]
    tgt = expected["target"]

    if p1["must_detect"]:
        matching = [
            s for s in result.specifications
            if tgt["file"] in s.file and tgt["func"] in s.entrypoint
        ]
        assert matching, (
            f"Phase 1 did not detect {tgt['func']!r} in {tgt['file']!r}.\n"
            f"Specs found: {[(s.file, s.entrypoint) for s in result.specifications]}"
        )
        spec = matching[0]
        assert p1["expected_rule_id"] in spec.rule_id, (
            f"Expected rule_id containing {p1['expected_rule_id']!r}, "
            f"got {spec.rule_id!r}"
        )
        assert spec.assertion_template == p1["expected_assertion_template"], (
            f"Expected template {p1['expected_assertion_template']!r}, "
            f"got {spec.assertion_template!r}"
        )
    assert len(result.specifications) >= p1["min_findings"], (
        f"Expected >= {p1['min_findings']} findings, "
        f"got {len(result.specifications)}"
    )


def assert_phase2(results: list[Phase2Result], expected: dict) -> None:
    """Assert Phase 2 output matches the expected.json phase2 section."""
    p2 = expected["phase2"]
    triggered = [r for r in results if r.outcome == SEOutcome.BUG_TRIGGERED]
    assert triggered, (
        f"Phase 2 did not trigger a bug. "
        f"Outcomes: {[r.outcome.value for r in results]}"
    )
    r = triggered[0]
    assert r.turns_used <= p2["max_turns"], (
        f"Phase 2 used {r.turns_used} turns, max allowed {p2['max_turns']}"
    )
    if r.witness:
        assert r.witness.ktest_paths, "BUG_TRIGGERED witness has no .ktest files"


def assert_phase3(p3_result, expected: dict) -> None:
    """Assert Phase 3 output matches the expected.json phase3 section."""
    p3 = expected["phase3"]
    confirmed = [
        r for r in p3_result.results
        if r.verdict == ValidationVerdict.CONFIRMED
    ]
    assert confirmed, (
        f"Phase 3 did not confirm the bug. "
        f"Verdicts: {[r.verdict.value for r in p3_result.results]}"
    )
    r = confirmed[0]
    assert r.asan_type == p3["expected_asan_type"], (
        f"Expected ASan type {p3['expected_asan_type']!r}, got {r.asan_type!r}"
    )
    assert p3["crash_must_be_in_file"] in r.file, (
        f"Crash in {r.file!r}, expected path containing "
        f"{p3['crash_must_be_in_file']!r}"
    )


# ---------------------------------------------------------------------------
# Phase 1 only (no Docker required)
# ---------------------------------------------------------------------------

@pytest.mark.e2e_phase1
def test_phase1_detects_vulnerability(
    workspace: tuple[Path, dict],
    tmp_path: Path,
) -> None:
    """Phase 1 must detect the vulnerability defined in expected.json.

    Uses pre-built SARIF fixtures — no CodeQL or Docker required.
    Writes fixtures/spec.json for downstream Phase 2/3 tests.
    """
    ws, expected = workspace
    tgt = expected["target"]

    # Copy workspace to tmp_path so the absolute path avoids /tests/ filtering
    src_copy = tmp_path / "src"
    shutil.copytree(ws, src_copy)

    result = _phase1_from_sarif(ws, src_copy, tmp_path / "phase1")
    assert_phase1(result, expected, ws)

    # Save normalized spec.json with a stable file path (independent of tmp_path)
    fixture_dir = ws / "fixtures"
    fixture_dir.mkdir(exist_ok=True)

    matching = [
        s for s in result.specifications if tgt["func"] in s.entrypoint
    ]
    if matching:
        spec_norm = _normalize_spec(matching[0], ws, tgt["file"])
        (fixture_dir / "spec.json").write_text(
            spec_norm.model_dump_json(indent=2), encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# Phase 2 only
# ---------------------------------------------------------------------------

@pytest.mark.e2e_phase2
def test_phase2_triggers_bug(
    workspace: tuple[Path, dict],
    docker_runner,
    tmp_path: Path,
) -> None:
    """Phase 2 must trigger a bug within max_turns.

    Loads fixtures/spec.json; skips if the fixture is missing.
    Uses real Anthropic API by default; MockLLMClient when E2E_MOCK_LLM=true.
    Writes fixtures/phase2_result.json and fixtures/witness.ktest.
    """
    ws, expected = workspace
    spec_path = load_fixture(ws, "spec.json")
    spec = VulnerabilitySpec.model_validate_json(spec_path.read_text(encoding="utf-8"))

    config = Phase2Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase2",
        docker_runner=docker_runner,
        T_max=expected["phase2"]["max_turns"],
        llm_client=resolve_llm_client(ws / "fixtures"),
    )
    results = Phase2Pipeline(config).run([spec])

    assert_phase2(results, expected)

    # Save fixtures for Phase 3
    fixture_dir = ws / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    triggered = next(
        (r for r in results if r.outcome == SEOutcome.BUG_TRIGGERED), None
    )
    if triggered:
        if triggered.witness and triggered.witness.ktest_paths:
            stable_ktest = fixture_dir / "witness.ktest"
            shutil.copy(triggered.witness.ktest_paths[0], stable_ktest)

            # Rewrite ktest_paths to the stable fixture path so Phase 3
            # can load phase2_result.json without relying on the /tmp/ dir.
            result_dict = json.loads(triggered.model_dump_json())
            result_dict["witness"]["ktest_paths"] = [str(stable_ktest)]
            (fixture_dir / "phase2_result.json").write_text(
                json.dumps(result_dict, indent=2), encoding="utf-8"
            )
        else:
            (fixture_dir / "phase2_result.json").write_text(
                triggered.model_dump_json(indent=2), encoding="utf-8"
            )


# ---------------------------------------------------------------------------
# Phase 3 only
# ---------------------------------------------------------------------------

@pytest.mark.e2e_phase3
def test_phase3_confirms_vulnerability(
    workspace: tuple[Path, dict],
    docker_runner,
    tmp_path: Path,
) -> None:
    """Phase 3 must confirm the vulnerability with ASan.

    Loads fixtures/spec.json and fixtures/phase2_result.json; skips if
    either is missing.  No LLM calls.  Writes fixtures/verified_bug.json.
    """
    ws, expected = workspace
    spec_path = load_fixture(ws, "spec.json")
    p2_result_path = load_fixture(ws, "phase2_result.json")

    spec = VulnerabilitySpec.model_validate_json(spec_path.read_text(encoding="utf-8"))
    p2_result = Phase2Result.model_validate_json(
        p2_result_path.read_text(encoding="utf-8")
    )

    runner = docker_runner

    # Copy source into the container so the ASan build can find it
    runner.setup_target(
        project_url=None,
        commit=None,
        build_commands=[],
        dependencies=["make"],
        local_source_path=str(ws),
    )
    container_src = f"/workspace/e2e-{ws.name}/src"

    config = Phase3Config(
        project_name=f"e2e-{ws.name}",
        # Container-side path: ResultClassifier._is_project_source() uses it
        project_root=Path(container_src),
        output_dir=tmp_path / "phase3",
        docker_runner=runner,
        build_command="make all",
    )
    p3_result = Phase3Pipeline(config).run([p2_result], [spec])

    assert_phase3(p3_result, expected)

    fixture_dir = ws / "fixtures"
    fixture_dir.mkdir(exist_ok=True)
    confirmed = next(
        (r for r in p3_result.results if r.verdict == ValidationVerdict.CONFIRMED),
        None,
    )
    if confirmed:
        (fixture_dir / "verified_bug.json").write_text(
            json.dumps(json.loads(confirmed.model_dump_json()), indent=2),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

@pytest.mark.e2e_full
def test_full_pipeline(
    workspace: tuple[Path, dict],
    docker_runner,
    tmp_path: Path,
) -> None:
    """Full Phase 1 → 2 → 3 pipeline.

    Runs the real Anthropic API by default.
    Validates all three phases against expected.json.
    A performance warning is emitted (not a failure) if over the time limit.
    """
    ws, expected = workspace
    runner = docker_runner
    start = time.perf_counter()
    tgt = expected["target"]

    # ── Phase 1 (pre-built SARIF, no Docker) ──────────────────────────────
    src_copy = tmp_path / "src"
    shutil.copytree(ws, src_copy)

    p1_result = _phase1_from_sarif(ws, src_copy, tmp_path / "phase1")
    assert_phase1(p1_result, expected, ws)

    target_specs = [
        s for s in p1_result.specifications if tgt["func"] in s.entrypoint
    ]
    assert target_specs, "Phase 1 found no spec for the target function"

    normalized_specs = [_normalize_spec(s, ws, tgt["file"]) for s in target_specs]

    # ── Phase 2 ────────────────────────────────────────────────────────────
    p2_config = Phase2Config(
        project_name=f"e2e-{ws.name}",
        project_root=ws,
        output_dir=tmp_path / "phase2",
        docker_runner=runner,
        T_max=expected["phase2"]["max_turns"],
    )
    p2_results = Phase2Pipeline(p2_config).run(normalized_specs)
    assert_phase2(p2_results, expected)

    # ── Phase 3 ────────────────────────────────────────────────────────────
    triggered = [r for r in p2_results if r.outcome == SEOutcome.BUG_TRIGGERED]

    runner.setup_target(
        project_url=None,
        commit=None,
        build_commands=[],
        dependencies=["make"],
        local_source_path=str(ws),
    )
    container_src = f"/workspace/e2e-{ws.name}/src"

    p3_config = Phase3Config(
        project_name=f"e2e-{ws.name}",
        project_root=Path(container_src),
        output_dir=tmp_path / "phase3",
        docker_runner=runner,
        build_command="make all",
    )
    p3_result = Phase3Pipeline(p3_config).run(triggered, normalized_specs)
    assert_phase3(p3_result, expected)

    elapsed = time.perf_counter() - start
    perf = expected["performance"]
    if elapsed > perf["max_wall_seconds"]:
        warnings.warn(
            f"Performance: {elapsed:.1f}s > limit {perf['max_wall_seconds']}s "
            f"for {ws.name}",
            UserWarning,
            stacklevel=2,
        )
