"""Phase 2 — SEDiagnoser: run KLEE and classify the symbolic execution outcome."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from sailor.models.schemas import SEDiagnostic, SEOutcome

logger = logging.getLogger("sailor.phase2.se_diagnoser")

# KLEE runs via Docker when the native binary is unavailable.
_DOCKER_IMAGE = "klee/klee"


class SEDiagnoser:
    """Execute KLEE on a compiled bitcode file and classify the outcome.

    All subprocess calls to KLEE go through this class.
    When *docker_runner* is provided, KLEE execution is delegated to
    :meth:`~sailor.infra.docker_runner.DockerRunner.run_klee` so all KLEE
    calls execute inside the runner container (CLAUDE.md Rule 2).

    Args:
        klee_path: Path or name of the klee executable (local fallback).
        timeout: Maximum KLEE wall-clock time in seconds.
        depth_limit: Maximum path depth for KLEE exploration.
        output_dir: Directory where KLEE output and .ktest files are stored.
        use_docker: If True, run KLEE inside the ``klee/klee`` Docker container
            (local fallback; ignored when docker_runner is set).
        docker_runner: When set, delegate KLEE execution to this runner instance.
    """

    def __init__(
        self,
        klee_path: str,
        timeout: int,
        depth_limit: int,
        output_dir: Path,
        use_docker: bool = False,
        docker_runner: object | None = None,
    ) -> None:
        self.klee_path = klee_path
        self.timeout = timeout
        self.depth_limit = depth_limit
        self.output_dir = Path(output_dir)
        self.use_docker = use_docker
        self._docker_runner = docker_runner
        self._klee_out = self.output_dir / "klee-out"

    def run(self, bitcode_path: str) -> SEDiagnostic:
        """Execute KLEE on *bitcode_path* and return a classified :class:`SEDiagnostic`.

        When *docker_runner* was supplied at construction time, delegates to
        :meth:`~sailor.infra.docker_runner.DockerRunner.run_klee` so KLEE
        runs inside the runner container.

        Args:
            bitcode_path: Absolute path to the linked harness.bc file.

        Returns:
            A :class:`SEDiagnostic` with outcome and coverage info.
        """
        # ── Runner delegation (CLAUDE.md Rule 2) ──────────────────────────
        if self._docker_runner is not None:
            import os
            spec_id = os.path.basename(os.path.dirname(bitcode_path))
            result = self._docker_runner.run_klee(spec_id)
            outcome_map = {
                "bug_triggered": SEOutcome.BUG_TRIGGERED,
                "site_reached": SEOutcome.SITE_REACHED,
                "not_reached": SEOutcome.NOT_REACHED,
            }
            outcome = outcome_map.get(result["outcome"], SEOutcome.NOT_REACHED)
            diag = SEDiagnostic(
                outcome=outcome,
                functions_entered=result.get("probes_entered", []),
                functions_missed=[],
                ktest_paths=result.get("ktest_paths", []),
                raw_output=result.get("stderr", "")[:4000],
            )
            logger.info(
                "Runner KLEE outcome: %s | entered=%s | ktests=%d",
                outcome.value,
                diag.functions_entered,
                len(diag.ktest_paths),
            )
            return diag

        # ── Local subprocess fallback ──────────────────────────────────────
        klee_out_dir = self.output_dir / "klee-last"
        # KLEE refuses to run if the output directory already exists — remove it first.
        if klee_out_dir.exists():
            shutil.rmtree(klee_out_dir)
        klee_out_dir.parent.mkdir(parents=True, exist_ok=True)

        cmd = self._build_klee_cmd(bitcode_path, str(klee_out_dir))
        logger.info("Running KLEE: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30,  # grace period over KLEE's own limit
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
        except subprocess.TimeoutExpired:
            logger.warning("KLEE process timed out at OS level.")
            return SEDiagnostic(
                outcome=SEOutcome.INCONCLUSIVE,
                raw_output="[OS timeout]",
            )
        except OSError as exc:
            logger.error("Failed to launch KLEE: %s", exc)
            return SEDiagnostic(
                outcome=SEOutcome.INCONCLUSIVE,
                raw_output=str(exc),
            )

        raw = stdout + "\n" + stderr
        outcome = self._parse_outcome(stdout, stderr, klee_out_dir)
        functions_entered, functions_missed = self._parse_coverage_probes(stderr)
        ktest_paths = self._collect_ktest_paths(klee_out_dir)

        diag = SEDiagnostic(
            outcome=outcome,
            functions_entered=functions_entered,
            functions_missed=functions_missed,
            ktest_paths=ktest_paths,
            raw_output=raw[:4000],
        )
        logger.info(
            "KLEE outcome: %s | entered=%s | missed=%s | ktests=%d",
            outcome.value,
            functions_entered,
            functions_missed,
            len(ktest_paths),
        )
        return diag

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_klee_cmd(self, bitcode_path: str, klee_out_dir: str) -> list[str]:
        """Build the full KLEE command list."""
        klee_flags = [
            "--search=random-path",
            "--search=dfs",
            f"--max-time={self.timeout}",
            f"--max-depth={self.depth_limit}",
            "--emit-all-errors",
            f"--output-dir={klee_out_dir}",
            bitcode_path,
        ]

        if self.use_docker:
            work_dir = str(Path(bitcode_path).parent)
            # Mount two levels up so both harness/ and klee-last/ are accessible
            mount_root = str(Path(bitcode_path).parent.parent)
            return [
                "docker", "run", "--rm",
                "-v", f"{mount_root}:{mount_root}",
                "-w", work_dir,
                _DOCKER_IMAGE,
                "klee",
            ] + klee_flags

        return [self.klee_path] + klee_flags

    def _parse_outcome(
        self, stdout: str, stderr: str, klee_out_dir: Path
    ) -> SEOutcome:
        """Classify KLEE output into one of the three terminal outcomes.

        Priority order: BUG_TRIGGERED > SITE_REACHED > NOT_REACHED.

        Args:
            stdout: KLEE standard output.
            stderr: KLEE standard error.
            klee_out_dir: Directory where KLEE wrote its output.

        Returns:
            The classified :class:`SEOutcome`.
        """
        combined = stdout + "\n" + stderr
        ktest_files = list(klee_out_dir.glob("*.ktest"))

        # SAILOR_SINK_REACHED assertion fires (may be an assertion fail .err or in raw output)
        # Check for KLEE assertion errors that contain SAILOR_SINK_REACHED
        has_sailor_assert = bool(
            re.search(r"SAILOR_SINK_REACHED", combined, re.I)
            or any(p.suffix == ".assert.err" for p in klee_out_dir.glob("*.err"))
        )

        # BUG_TRIGGERED: a REAL memory error (not just our assertion) AND .ktest files exist.
        # Exclude assertion-only errors by checking for non-assert error files.
        real_error_files = [p for p in klee_out_dir.glob("*.err")
                            if not p.name.endswith(".assert.err")]
        has_real_memory_error = bool(
            re.search(r"memory error|invalid memory access", combined, re.I)
            or real_error_files
        )
        if has_real_memory_error and ktest_files:
            return SEOutcome.BUG_TRIGGERED

        # SITE_REACHED: our reachability assertion fired (or any KLEE error with ktest)
        if has_sailor_assert and ktest_files:
            return SEOutcome.SITE_REACHED

        # NOT_REACHED: KLEE ran but neither condition triggered
        return SEOutcome.NOT_REACHED

    def _parse_coverage_probes(self, stderr: str) -> tuple[list[str], list[str]]:
        """Parse SPINE_PROBE coverage markers from KLEE stderr.

        Args:
            stderr: KLEE stderr text.

        Returns:
            ``(functions_entered, functions_missed)`` — both are lists of
            function names.  ``functions_missed`` is always empty here (the
            caller knows the expected chain and can diff against entered).
        """
        probe_re = re.compile(r'SPINE_PROBE:(\w+):ENTRY')
        entered = list(dict.fromkeys(probe_re.findall(stderr)))  # ordered, unique
        return entered, []

    def _collect_ktest_paths(self, klee_out_dir: Path) -> list[str]:
        """Collect all .ktest file paths from the KLEE output directory.

        Args:
            klee_out_dir: Path to the KLEE output directory.

        Returns:
            Sorted list of absolute .ktest file paths.
        """
        return sorted(str(p) for p in klee_out_dir.glob("*.ktest"))
