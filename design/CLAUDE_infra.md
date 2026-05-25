# CLAUDE_infra.md — Docker + Celery Infrastructure Design

> Claude Code reads this file during Session 0 — Infrastructure Setup.
> This session must complete before Sessions 2-7.
> All Absolute Rules in CLAUDE.md apply.

---

## Core Principle

```
ALL services start with a single command: docker compose up -d
No manual setup steps. No local toolchain required beyond Docker.

LOCAL MACHINE (Claude Code territory):
  sailor/ package code only
  Docker image build
  Celery task definition
  Result collection from DB

DOCKER CONTAINERS (all execution):
  frontend/    → React + Vite dev server (or nginx for prod)
  backend/     → FastAPI + Uvicorn
  worker/      → Celery worker (sailor/ package)
  runner/      → Ephemeral per-CVE container (codeql + klee + clang)
  redis        → Celery broker + result backend + SSE event bus
  postgres     → State store (runs, specs, turns, verdicts)
  minio        → Artifact store (S3-compatible)

NEVER:
  git clone target source to local machine
  apt install on local machine
  make/build on local machine
  klee/clang/codeql run on local machine directly
```

---

## Target Architecture

```
         docker compose up -d
                │
    ┌───────────┼───────────────────────────┐
    │           │                           │
    ▼           ▼                           ▼
┌───────┐  ┌─────────┐              ┌────────────┐
│  FE   │  │   BE    │              │   Worker   │
│ React │  │ FastAPI │              │   Celery   │
│ :3000 │  │  :8000  │              │            │
└───┬───┘  └────┬────┘              └─────┬──────┘
    │  API calls │                        │ spawns
    └────────────┘                        ▼
                │            ┌────────────────────────┐
                │            │  Runner (ephemeral)     │
                │            │  ubuntu + codeql        │
                │            │  + klee + clang         │
                │            │  per CVE, auto-removed  │
                │            └────────────┬───────────┘
                │                         │
    ┌───────────┼─────────────────────────┼──────────┐
    ▼           ▼                         ▼          ▼
┌───────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Redis │  │ Postgres │  │  MinIO   │  │  Volume  │
│ :6379 │  │  :5432   │  │  :9000   │  │ /data/   │
└───────┘  └──────────┘  └──────────┘  └──────────┘
```

---

## File Structure

```
project_root/
├── docker-compose.yml           ← single entry point: docker compose up -d
├── .env                         ← all secrets + config (never committed)
├── .env.example                 ← committed template with placeholders
│
├── frontend/                    ← React web UI
│   ├── Dockerfile               ← multi-stage: build → nginx serve
│   ├── nginx.conf               ← API proxy + SPA fallback
│   └── src/
│
├── backend/                     ← FastAPI application
│   ├── Dockerfile
│   └── ...
│
├── sailor/                      ← Pipeline package (imported by worker)
│   └── infra/
│       ├── docker_runner.py     ← DockerRunner (all Phase execution)
│       ├── celery_tasks.py      ← Evaluation-only tasks (EvaluationDB/CVERecord)
│       └── celery_config.py     ← Evaluation-only Celery config
│
├── backend/                     ← FastAPI application + web-app Celery tasks
│   ├── celery_app.py            ← Celery app for the web application
│   └── tasks/
│       ├── phase1.py            ← Web-app Phase 1 task (PostgreSQL ORM)
│       ├── phase2.py            ← Web-app Phase 2 task (lease + heartbeat)
│       ├── phase3.py            ← Web-app Phase 3 task (verdict persistence)
│       └── exports.py           ← Tarball generation task
│
└── docker/
    ├── Dockerfile.worker        ← Celery worker (backend + sailor package)
    └── Dockerfile.runner        ← Phase execution (codeql + klee + clang)
```

---

## File 1: `sailor/infra/docker_runner.py`

```python
"""
DockerRunner: executes all Phase operations inside an ephemeral container.
The local machine never runs codeql, klee, clang, make, or git clone.
"""

import subprocess
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("sailor.infra.docker_runner")


@dataclass
class RunnerConfig:
    image: str = "sailor-runner:latest"
    workspace_base: Path = Path("/data/workspace")
    output_base: Path = Path("/data/output")
    network: str = "sailor_net"
    # Resource limits
    cpu_limit: str = "4"
    memory_limit: str = "8g"
    # Timeouts
    build_timeout: int = 1800        # 30 min for target build
    codeql_timeout: int = 3600       # 1 hr for CodeQL
    klee_timeout_per_run: int = 300  # 5 min per KLEE run (paper: T_klee=300s)
    asan_timeout: int = 60


class DockerRunner:
    """
    Manages an ephemeral Docker container for one CVE evaluation.
    One DockerRunner instance = one container = one CVE.

    All Phase 1/2/3 operations execute INSIDE the container.
    Results are written to a shared volume and collected as JSON.
    """

    def __init__(self, cve_id: str, config: RunnerConfig):
        self.cve_id = cve_id
        self.config = config
        self.container_id: str | None = None
        self.workspace = config.workspace_base / cve_id
        self.output_dir = config.output_base / cve_id

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Start the runner container.
        Mounts workspace and output as volumes.
        Does NOT clone or build anything yet.
        """
        cmd = [
            "docker", "run", "-d",
            "--name", f"sailor-runner-{self.cve_id}",
            "--network", self.config.network,
            "--cpus", self.config.cpu_limit,
            "--memory", self.config.memory_limit,
            "-v", f"{self.config.workspace_base}:/workspace",
            "-v", f"{self.config.output_base}:/output",
            "-e", f"CVE_ID={self.cve_id}",
            self.config.image,
            "sleep", "infinity",   # keep alive for exec calls
        ]
        result = self._local_run(cmd)
        self.container_id = result.stdout.strip()
        log.info(f"[{self.cve_id}] Container started: {self.container_id[:12]}")

    def stop(self) -> None:
        """Stop and remove the container. Always call in finally block."""
        if self.container_id:
            self._local_run(["docker", "rm", "-f", self.container_id],
                            check=False)
            log.info(f"[{self.cve_id}] Container removed.")
            self.container_id = None

    # ── Target Setup ───────────────────────────────────────────────────

    def setup_target(self, project_url: str | None, commit: str | None,
                     build_commands: list[str],
                     dependencies: list[str],
                     local_source_path: str | None = None) -> Path:
        """
        Inside container:
          1. apt-get install dependencies
          2. git clone + checkout commit  (OR docker cp from local_source_path)
          3. run build_commands
        Returns path to project root inside container.

        Exactly one of project_url or local_source_path must be provided.
        local_source_path is used by e2e tests where the target is a local dir.
        """
        if local_source_path and project_url:
            raise ValueError("Provide local_source_path OR project_url, not both.")
        if not local_source_path and not project_url:
            raise ValueError("Provide either local_source_path or project_url.")

        if dependencies:
            self.exec(
                f"apt-get update -qq && "
                f"apt-get install -y --no-install-recommends "
                f"{' '.join(dependencies)}",
                timeout=600,
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

    def copy_local_source(self, local_path: str) -> str:
        """Copy a local directory into the container via docker cp.

        Used by e2e tests where the target is a local C file, not a git repo.
        Returns: absolute path inside the container.
        """
        container_path = f"/workspace/{self.cve_id}/src"
        self.exec(f"mkdir -p {container_path}")
        result = self._local_run(
            ["docker", "cp", f"{local_path}/.", f"{self.container_id}:{container_path}"],
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"[{self.cve_id}] docker cp failed: {result.stderr}")
        return container_path

    # ── Phase 1 ────────────────────────────────────────────────────────

    def run_phase1(self, project_dir: str,
                   build_command: str) -> dict[str, Any]:
        """
        Inside container: build CodeQL DB + run 34 queries.
        Returns parsed SARIF as dict.
        """
        db_path = f"/workspace/{self.cve_id}/codeql_db"
        sarif_path = f"/output/{self.cve_id}/findings.sarif"

        # Build CodeQL DB
        self.exec(
            f"codeql database create {db_path} "
            f"--language=cpp "
            f"--command='{build_command}' "
            f"--source-root={project_dir} "
            f"--overwrite",
            cwd=project_dir,
            timeout=self.config.codeql_timeout,
        )

        # Run query suite
        self.exec(
            f"codeql database analyze {db_path} "
            f"/sailor-queries/ "
            f"--format=sarifv2.1.0 "
            f"--output={sarif_path}",
            timeout=self.config.codeql_timeout,
        )

        # Read result from shared volume (output is on host via mount)
        host_sarif = self.config.output_base / self.cve_id / "findings.sarif"
        return json.loads(host_sarif.read_text())

    # ── Phase 2 ────────────────────────────────────────────────────────

    def compile_harness(self, driver_c: str, slice_c: str,
                        include_paths: list[str]) -> tuple[bool, str]:
        """
        Inside container: compile driver + slice to LLVM bitcode.
        Returns (success, diagnostic_message).

        IMPORTANT: source files are written via docker cp from a temp dir
        (not via the shared volume path which may be root-owned after
        exec mkdir — see CLAUDE.md Known Issues Session 8).
        """
        import tempfile
        from pathlib import Path as _Path

        harness_dir = f"/workspace/{self.cve_id}/harness"
        self.exec(f"mkdir -p {harness_dir}")

        # Use docker cp so we never write to the root-owned volume path
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = _Path(tmpdir)
            (tmp / "driver.c").write_text(driver_c, encoding="utf-8")
            (tmp / "slice.c").write_text(slice_c, encoding="utf-8")
            cp = self._local_run(
                ["docker", "cp", f"{tmpdir}/.", f"{self.container_id}:{harness_dir}"],
                check=False,
            )
            if cp.returncode != 0:
                return False, f"docker cp harness files failed: {cp.stderr}"

        includes = " ".join(f"-I{p}" for p in include_paths) if include_paths else ""

        # Compile each source to bitcode
        for src, out in [("driver.c", "driver.bc"), ("slice.c", "slice.bc")]:
            r = self.exec(
                f"clang -O0 -g -emit-llvm -c "
                f"-Xclang -disable-O0-optnone "
                f"{includes} "
                f"{harness_dir}/{src} -o {harness_dir}/{out}",
                check=False,
            )
            if r["exit_code"] != 0:
                return False, r["stderr"]

        # Link
        link_result = self.exec(
            f"llvm-link {harness_dir}/driver.bc {harness_dir}/slice.bc "
            f"-o {harness_dir}/harness.bc",
            check=False,
        )
        if link_result["exit_code"] != 0:
            return False, link_result["stderr"]

        return True, ""

    def run_klee(self, spec_id: str) -> dict[str, Any]:
        """
        Inside container: run KLEE on compiled harness.
        Returns outcome dict: {outcome, ktest_paths, stderr, probes_entered}
        Paper settings: dual-strategy, T_klee=300s, depth=1000
        """
        harness_bc = f"/workspace/{self.cve_id}/harness/harness.bc"
        klee_out = f"/workspace/{self.cve_id}/klee-out-{spec_id}"

        result = self.exec(
            f"klee "
            f"--search=random-path --search=dfs "
            f"--max-time={self.config.klee_timeout_per_run} "
            f"--max-depth=1000 "
            f"--emit-all-errors "
            f"--output-dir={klee_out} "
            f"{harness_bc}",
            timeout=self.config.klee_timeout_per_run + 30,
            check=False,
        )

        stderr = result["stderr"]

        # Collect .ktest files via shared volume (always, before deciding outcome)
        host_klee_out = (
            self.config.workspace_base / self.cve_id / f"klee-out-{spec_id}"
        )
        ktest_paths: list[str] = []
        if host_klee_out.exists():
            ktest_paths = sorted(str(p) for p in host_klee_out.glob("*.ktest"))

        # Parse outcome: case-insensitive check for memory errors
        real_error = (
            "memory error" in stderr.lower()
            or "invalid memory access" in stderr.lower()
        )
        sailor_assert = "SAILOR_SINK_REACHED" in stderr

        if real_error and ktest_paths:
            outcome = "bug_triggered"
        elif sailor_assert and ktest_paths:
            outcome = "site_reached"
        else:
            outcome = "not_reached"

        # Parse coverage probes
        probes_entered = [
            line.split("SPINE_PROBE:")[1].split(":")[0]
            for line in stderr.splitlines()
            if "SPINE_PROBE:" in line and ":" in line.split("SPINE_PROBE:")[1]
        ]

        return {
            "outcome": outcome,
            "ktest_paths": ktest_paths,
            "stderr": stderr,
            "probes_entered": probes_entered,
        }

    # ── Phase 3 ────────────────────────────────────────────────────────

    def build_asan_archive(self, project_dir: str,
                           build_command: str) -> str:
        """
        Inside container: rebuild project with ASan flags.
        Returns path to .a archive inside container.
        """
        asan_dir = f"/workspace/{self.cve_id}/asan-build"
        self.exec(f"mkdir -p {asan_dir}")

        # Rebuild with ASan — UNMODIFIED project source
        self.exec(
            f"CFLAGS='-fsanitize=address -O1 -g' "
            f"CXXFLAGS='-fsanitize=address -O1 -g' "
            f"LDFLAGS='-fsanitize=address' "
            f"{build_command}",
            cwd=project_dir,
            timeout=self.config.build_timeout,
        )

        # Package as archive
        archive_path = f"{asan_dir}/project_asan.a"
        self.exec(
            f"find {project_dir} -name '*.o' | "
            f"xargs ar rcs {archive_path}"
        )
        return archive_path

    def run_asan_replay(self, replay_driver_c: str,
                        asan_archive: str,
                        include_paths: list[str]) -> dict[str, Any]:
        """
        Inside container: compile replay driver + run against ASan archive.
        Returns {crashed, asan_output}.
        """
        import tempfile
        from pathlib import Path as _Path

        replay_dir = f"/workspace/{self.cve_id}/replay"
        self.exec(f"mkdir -p {replay_dir}")

        # Write replay_driver.c via docker cp to avoid root-owned volume path
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = _Path(tmpdir)
            (tmp / "replay_driver.c").write_text(replay_driver_c, encoding="utf-8")
            cp = self._local_run(
                ["docker", "cp", f"{tmpdir}/.", f"{self.container_id}:{replay_dir}"],
                check=False,
            )
            if cp.returncode != 0:
                return {
                    "crashed": False,
                    "asan_output": f"docker cp replay_driver failed: {cp.stderr}",
                    "error": "compile_failed",
                }

        includes = " ".join(f"-I{p}" for p in include_paths) if include_paths else ""

        # Compile
        compile_result = self.exec(
            f"clang -fsanitize=address -O1 -g "
            f"{includes} "
            f"{replay_dir}/replay_driver.c "
            f"{asan_archive} "
            f"-o {replay_dir}/reproducer",
            check=False,
        )
        if compile_result["exit_code"] != 0:
            return {"crashed": False,
                    "asan_output": compile_result["stderr"],
                    "error": "compile_failed"}

        # Execute
        run_result = self.exec(
            f"ASAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "
            f"{replay_dir}/reproducer",
            timeout=self.config.asan_timeout,
            check=False,
        )

        asan_output = run_result["stdout"] + run_result["stderr"]
        crashed = (run_result["exit_code"] != 0
                   or "ERROR: AddressSanitizer" in asan_output)

        return {"crashed": crashed, "asan_output": asan_output}

    # ── Internal exec ──────────────────────────────────────────────────

    def exec(self, command: str, cwd: str | None = None,
             timeout: int = 300, check: bool = True) -> dict[str, Any]:
        """
        Run a shell command INSIDE the container via docker exec.
        All Phase 1/2/3 commands go through here.
        Never runs on the local machine.
        """
        if not self.container_id:
            raise RuntimeError("Container not started")

        cmd = ["docker", "exec"]
        if cwd:
            cmd += ["-w", cwd]
        cmd += [self.container_id, "bash", "-c", command]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"[{self.cve_id}] Command timed out ({timeout}s): {command[:80]}"
            )

        log.debug(f"[{self.cve_id}] exec exit={result.returncode}: "
                  f"{command[:60]}")

        if check and result.returncode != 0:
            raise RuntimeError(
                f"[{self.cve_id}] Command failed (exit {result.returncode}):\n"
                f"  cmd: {command[:120]}\n"
                f"  stderr: {result.stderr[:500]}"
            )

        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def _local_run(self, cmd: list[str],
                   check: bool = True) -> subprocess.CompletedProcess:
        """Run a command on the LOCAL machine (docker CLI only)."""
        return subprocess.run(
            cmd, capture_output=True, text=True, check=check
        )
```

---

## File 2: `sailor/infra/celery_tasks.py` (standalone evaluation pipeline only)

> **Architecture note**: The web application uses Celery tasks defined in
> `backend/tasks/phase1.py`, `phase2.py`, `phase3.py` with the FastAPI ORM
> (PostgreSQL + SQLAlchemy). The file below (`sailor/infra/celery_tasks.py`)
> is used only by the **standalone evaluation pipeline** (`sailor/evaluation/`)
> which uses a SQLite `EvaluationDB` instead of the web-app state store.
> Never import `sailor.infra.celery_tasks` from backend code.

```python
"""
Celery task definitions for the standalone evaluation pipeline (Sailor Phase 1/2/3).
Each task runs inside a DockerRunner container.
Results are saved to EvaluationDB (SQLite) immediately (DB checkpoint).
"""

from celery import Celery
from pathlib import Path
import logging

from sailor.infra.docker_runner import DockerRunner, RunnerConfig
from sailor.evaluation.db import EvaluationDB, PhaseStatus, FailureReason
from sailor.phase1.pipeline import Phase1Pipeline, Phase1Config
from sailor.phase2.pipeline import Phase2Pipeline, Phase2Config
from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config
from sailor.models.schemas import CVERecord

log = logging.getLogger("sailor.infra.celery_tasks")

# Celery app — broker and backend configured via env vars
celery_app = Celery("sailor")
celery_app.config_from_object("sailor.infra.celery_config")


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def run_phase1_task(self, eval_id: str, cve_record: dict,
                    db_path: str, output_base: str) -> dict:
    """
    Celery task: run Phase 1 for one CVE inside a Docker container.

    Execution:
      1. Start DockerRunner container
      2. Setup target (clone + build) inside container
      3. Run Phase 1 (CodeQL) inside container
      4. Save result to EvaluationDB
      5. Stop container (always, even on failure)

    Returns: {"status": "completed"|"failed", "findings_count": N}
    """
    db = EvaluationDB(Path(db_path))
    record = CVERecord(**cve_record)
    runner = DockerRunner(
        cve_id=record.cve_id,
        config=RunnerConfig(output_base=Path(output_base)),
    )

    db.update_phase_status(eval_id, phase=1, status=PhaseStatus.RUNNING)

    try:
        runner.start()

        # Setup target INSIDE container
        project_dir = runner.setup_target(
            project_url=record.project_url,
            commit=record.vulnerable_commit,
            build_commands=record.build_commands,
            dependencies=record.dependencies,
        )

        # Run Phase 1 INSIDE container
        sarif_dict = runner.run_phase1(
            project_dir=str(project_dir),
            build_command=record.build_commands[-1],
        )

        # Parse results using Phase1Pipeline (locally — no container needed)
        config = Phase1Config(
            project_name=record.project,
            project_root=project_dir,
            output_dir=Path(output_base) / record.cve_id / "phase1",
            prebuilt_sarif=sarif_dict,   # inject pre-built SARIF
        )
        result = Phase1Pipeline(config).run_from_sarif(sarif_dict)

        # Save to DB immediately (checkpoint)
        db.update_phase_status(
            eval_id, phase=1,
            status=PhaseStatus.COMPLETED,
            result_json=result.model_dump_json(),
        )
        log.info(f"[{record.cve_id}] Phase 1 completed: "
                 f"{result.total_findings} findings, "
                 f"{result.after_filtering} active")
        return {"status": "completed",
                "findings_count": result.after_filtering}

    except Exception as exc:
        db.update_phase_status(
            eval_id, phase=1,
            status=PhaseStatus.FAILED,
            failure_reason=FailureReason.UNKNOWN,
            failure_detail=str(exc),
        )
        log.error(f"[{record.cve_id}] Phase 1 failed: {exc}")
        raise self.retry(exc=exc)

    finally:
        runner.stop()   # always remove container


@celery_app.task(bind=True, max_retries=1, default_retry_delay=30)
def run_phase2_task(self, eval_id: str, cve_record: dict,
                    spec_json: str, db_path: str,
                    output_base: str, llm_model: str) -> dict:
    """
    Celery task: run Phase 2 (LLM + KLEE) for one VulnerabilitySpec.

    The LLM orchestrator runs LOCALLY (LLM API calls).
    compile_harness() and run_klee() execute INSIDE the container.
    """
    from sailor.models.schemas import VulnerabilitySpec
    import json

    db = EvaluationDB(Path(db_path))
    record = CVERecord(**cve_record)
    spec = VulnerabilitySpec(**json.loads(spec_json))
    runner = DockerRunner(
        cve_id=record.cve_id,
        config=RunnerConfig(output_base=Path(output_base)),
    )

    db.update_phase_status(eval_id, phase=2, status=PhaseStatus.RUNNING)

    try:
        runner.start()

        # Setup target again (container is ephemeral)
        project_dir = runner.setup_target(
            project_url=record.project_url,
            commit=record.vulnerable_commit,
            build_commands=record.build_commands,
            dependencies=record.dependencies,
        )

        # Phase 2: LLM orchestrator runs locally,
        # but compile/KLEE calls go through runner
        config = Phase2Config(
            project_name=record.project,
            project_root=project_dir,
            output_dir=Path(output_base) / record.cve_id / "phase2",
            llm_model=llm_model,
            docker_runner=runner,   # inject runner for compile/KLEE
        )
        result = Phase2Pipeline(config).run([spec])

        db.update_phase_status(
            eval_id, phase=2,
            status=PhaseStatus.COMPLETED,
            result_json=result[0].model_dump_json() if result else "[]",
        )
        outcome = result[0].outcome if result else "inconclusive"
        log.info(f"[{record.cve_id}] Phase 2 completed: {outcome}")
        return {"status": "completed", "outcome": outcome}

    except Exception as exc:
        db.update_phase_status(
            eval_id, phase=2,
            status=PhaseStatus.FAILED,
            failure_detail=str(exc),
        )
        log.error(f"[{record.cve_id}] Phase 2 failed: {exc}")
        raise self.retry(exc=exc)

    finally:
        runner.stop()


@celery_app.task(bind=True, max_retries=1)
def run_phase3_task(self, eval_id: str, cve_record: dict,
                    witness_json: str, spec_json: str,
                    db_path: str, output_base: str) -> dict:
    """
    Celery task: run Phase 3 (ASan validation) inside container.

    Uses UNMODIFIED project source compiled with ASan inside container.
    Never uses LLM-generated stubs for ASan compilation.
    """
    import json
    from sailor.models.schemas import WitnessInput, VulnerabilitySpec

    db = EvaluationDB(Path(db_path))
    record = CVERecord(**cve_record)
    witness = WitnessInput(**json.loads(witness_json))
    spec = VulnerabilitySpec(**json.loads(spec_json))
    runner = DockerRunner(
        cve_id=record.cve_id,
        config=RunnerConfig(output_base=Path(output_base)),
    )

    db.update_phase_status(eval_id, phase=3, status=PhaseStatus.RUNNING)

    try:
        runner.start()

        project_dir = runner.setup_target(
            project_url=record.project_url,
            commit=record.vulnerable_commit,
            build_commands=record.build_commands,
            dependencies=record.dependencies,
        )

        config = Phase3Config(
            project_name=record.project,
            project_root=project_dir,
            output_dir=Path(output_base) / record.cve_id / "phase3",
            docker_runner=runner,   # inject runner for ASan build/exec
        )
        p3_result = Phase3Pipeline(config).run([witness], [spec])

        db.update_phase_status(
            eval_id, phase=3,
            status=PhaseStatus.COMPLETED,
            result_json=p3_result.model_dump_json(),
        )
        confirmed = p3_result.confirmed
        log.info(f"[{record.cve_id}] Phase 3: confirmed={confirmed}")
        return {"status": "completed", "confirmed": confirmed}

    except Exception as exc:
        db.update_phase_status(
            eval_id, phase=3,
            status=PhaseStatus.FAILED,
            failure_detail=str(exc),
        )
        raise self.retry(exc=exc)

    finally:
        runner.stop()
```

---

## File 3: `docker/Dockerfile.runner`

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ── System tools ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl wget ca-certificates \
    autoconf automake libtool pkg-config bear \
    libz-dev libssl-dev flex bison \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── LLVM / Clang (for KLEE + ASan) ────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-14 llvm-14 llvm-14-dev llvm-14-tools \
    libclang-14-dev \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-14   100 \
 && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-14 100 \
 && update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-14 100

# ── KLEE ───────────────────────────────────────────────────────────────
# Build from source or use pre-built package
# Option A: pre-built (faster)
RUN pip3 install klee-build-dependencies 2>/dev/null || true
# Option B: install from KLEE docker image (recommended)
COPY --from=klee/klee:latest /usr/local/bin/klee /usr/local/bin/klee
COPY --from=klee/klee:latest /usr/local/bin/ktest-tool /usr/local/bin/ktest-tool
COPY --from=klee/klee:latest /usr/local/include/klee /usr/local/include/klee
COPY --from=klee/klee:latest /usr/local/lib/libkleeRuntest.so /usr/local/lib/

# ── CodeQL ─────────────────────────────────────────────────────────────
ARG CODEQL_VERSION=2.16.5
RUN wget -q \
    https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-linux64.tar.gz \
    -O /tmp/codeql.tar.gz \
    && tar -xzf /tmp/codeql.tar.gz -C /usr/local/ \
    && rm /tmp/codeql.tar.gz
ENV PATH="/usr/local/codeql:${PATH}"

# ── Sailor CodeQL queries (mounted or baked in) ────────────────────────
RUN mkdir -p /sailor-queries
# Custom queries are mounted at runtime via volume:
#   -v ./sailor/codeql/queries:/sailor-queries

WORKDIR /workspace
```

---

## File 4: `docker/Dockerfile.worker`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies from the backend directory
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code (tasks/, celery_app.py, config.py, database.py, services/, etc.)
COPY backend/ ./

# Copy sailor package — used by phase tasks via DockerRunner
COPY sailor/ ./sailor/

# Worker runs tasks.phase1/2/3 from the backend celery app
CMD ["celery", "-A", "celery_app", "worker", \
     "--loglevel=info", \
     "--concurrency=4", \
     "-Q", "phase1,phase2,phase3"]
```

> Note: The worker uses `backend/celery_app.py` (not `sailor/infra/celery_tasks.py`).
> `sailor/infra/celery_tasks.py` is used only by the standalone evaluation pipeline
> (e.g. `sailor/evaluation/pipeline.py`). Web-app Celery tasks live in `backend/tasks/`.

---

## `docker-compose.yml` (project root — single entry point)

```yaml
# docker-compose.yml
# Usage: docker compose up -d
# All services start automatically. No manual setup required.

services:

  # ── Frontend ────────────────────────────────────────────────────────
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
      target: ${FRONTEND_TARGET:-production}   # development | production
    ports:
      - "${FRONTEND_PORT:-3000}:80"
    environment:
      VITE_API_URL: http://backend:8000
    depends_on:
      backend:
        condition: service_healthy
    networks: [sailor_net]
    restart: unless-stopped

  # ── Backend (FastAPI) ───────────────────────────────────────────────
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "${BACKEND_PORT:-8000}:8000"
    environment:
      DATABASE_URL:          postgresql+asyncpg://sailor:${DB_PASSWORD}@postgres:5432/sailor
      REDIS_URL:             redis://redis:6379/0
      CELERY_BROKER_URL:     redis://redis:6379/0
      CELERY_RESULT_BACKEND: redis://redis:6379/1
      S3_ENDPOINT:           http://minio:9000
      S3_ACCESS_KEY:         ${MINIO_ROOT_USER}
      S3_SECRET_KEY:         ${MINIO_ROOT_PASSWORD}
      S3_BUCKET:             sailor-artifacts
      JWT_SECRET:            ${JWT_SECRET}
      ANTHROPIC_API_KEY:     ${ANTHROPIC_API_KEY:-}
      ANTHROPIC_API_OPTION:  ${ANTHROPIC_API_OPTION:-false}
      GEMINI_API_KEY:        ${GEMINI_API_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      minio:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks: [sailor_net]
    restart: unless-stopped

  # ── Celery Worker ───────────────────────────────────────────────────
  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.worker
    environment:
      CELERY_BROKER_URL:     redis://redis:6379/0
      CELERY_RESULT_BACKEND: redis://redis:6379/1
      DATABASE_URL:          postgresql+asyncpg://sailor:${DB_PASSWORD}@postgres:5432/sailor
      ANTHROPIC_API_KEY:     ${ANTHROPIC_API_KEY:-}
      ANTHROPIC_API_OPTION:  ${ANTHROPIC_API_OPTION:-false}
      GEMINI_API_KEY:        ${GEMINI_API_KEY}
      OUTPUT_BASE:           /data/output
      RUNNER_IMAGE:          sailor-runner:latest
      RUNNER_NETWORK:        sailor_net
    volumes:
      - workspace_data:/data/workspace
      - output_data:/data/output
      - /var/run/docker.sock:/var/run/docker.sock   # spawn runner containers
      - ./sailor/codeql/queries:/sailor-queries:ro  # custom CodeQL queries
    depends_on:
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    networks: [sailor_net]
    restart: unless-stopped

  # ── Redis ───────────────────────────────────────────────────────────
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks: [sailor_net]
    restart: unless-stopped

  # ── PostgreSQL ──────────────────────────────────────────────────────
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB:       sailor
      POSTGRES_USER:     sailor
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - db_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sailor"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks: [sailor_net]
    restart: unless-stopped

  # ── MinIO (S3-compatible artifact store) ───────────────────────────
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER:     ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    ports:
      - "${MINIO_CONSOLE_PORT:-9001}:9001"   # admin console (optional)
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks: [sailor_net]
    restart: unless-stopped

  # ── MinIO bucket init (runs once, exits) ──────────────────────────
  minio-init:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
        mc alias set local http://minio:9000 $${MINIO_ROOT_USER} $${MINIO_ROOT_PASSWORD};
        mc mb --ignore-existing local/sailor-artifacts;
        mc anonymous set none local/sailor-artifacts;
        echo 'MinIO bucket ready.';
      "
    environment:
      MINIO_ROOT_USER:     ${MINIO_ROOT_USER}
      MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
    networks: [sailor_net]

volumes:
  db_data:
  redis_data:
  minio_data:
  workspace_data:
  output_data:

networks:
  sailor_net:
    driver: bridge
```

---

## `.env.example`

```bash
# Copy to .env and fill in values before running docker compose up -d

# Database
DB_PASSWORD=changeme

# JWT
JWT_SECRET=change-this-to-a-random-64-char-string

# MinIO
MINIO_ROOT_USER=sailor
MINIO_ROOT_PASSWORD=changeme123

# LLM (Gemini is default — ANTHROPIC_API_OPTION must be "true" to use Claude)
GEMINI_API_KEY=your-gemini-api-key-here
ANTHROPIC_API_KEY=                        # optional — only needed if ANTHROPIC_API_OPTION=true
ANTHROPIC_API_OPTION=false                # set to "true" to use Claude instead of Gemini

# Ports (optional — change only if defaults conflict)
FRONTEND_PORT=3000
BACKEND_PORT=8000
MINIO_CONSOLE_PORT=9001

# Build target (development | production)
FRONTEND_TARGET=production
```
