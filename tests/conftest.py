"""pytest configuration and shared fixtures for e2e tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sailor.infra.docker_runner import DockerRunner, RunnerConfig

WORKSPACE_ROOT = Path(__file__).parent / "e2e_workspace"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e_full: full Phase 1→2→3 pipeline test")
    config.addinivalue_line("markers", "e2e_phase1: Phase 1 only (no Docker required)")
    config.addinivalue_line("markers", "e2e_phase2: Phase 2 only")
    config.addinivalue_line("markers", "e2e_phase3: Phase 3 only")


@pytest.fixture(params=["cwe_122", "cwe_121", "cwe_416", "cwe_476"])
def workspace(request: pytest.FixtureRequest) -> tuple[Path, dict]:
    """Yield (workspace_path, expected) for each CWE directory."""
    path = WORKSPACE_ROOT / request.param
    expected = json.loads((path / "expected.json").read_text(encoding="utf-8"))
    return path, expected


@pytest.fixture
def cwe_122_workspace() -> tuple[Path, dict]:
    """Single workspace fixture for validation tests."""
    path = WORKSPACE_ROOT / "cwe_122"
    expected = json.loads((path / "expected.json").read_text(encoding="utf-8"))
    return path, expected


@pytest.fixture
def docker_runner(workspace: tuple[Path, dict]) -> DockerRunner:
    """Start a DockerRunner for one test workspace; stop it after the test."""
    path, _ = workspace
    workspace_base = Path("/tmp/e2e_workspace")
    output_base = Path("/tmp/e2e_output")
    workspace_base.mkdir(parents=True, exist_ok=True)
    output_base.mkdir(parents=True, exist_ok=True)

    # Pre-create the cve_id subdirectory as the current user so that
    # Docker (running as root inside the container) cannot claim ownership
    # of this directory first and make it unwritable by compile_harness().
    (workspace_base / f"e2e-{path.name}").mkdir(parents=True, exist_ok=True)

    runner = DockerRunner(
        cve_id=f"e2e-{path.name}",
        config=RunnerConfig(
            image="sailor-runner:latest",
            workspace_base=workspace_base,
            output_base=output_base,
            network="bridge",
        ),
    )
    runner.start()
    yield runner
    runner.stop()
