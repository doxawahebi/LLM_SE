"""Phase 3 — Concrete Executor.

Executes the ASan-instrumented reproducer binary and captures its output for
downstream classification.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger("sailor.phase3.concrete_executor")

_ASAN_OPTIONS = "halt_on_error=1:print_stacktrace=1"


class ConcreteExecutor:
    """Execute a reproducer binary and capture ASan output.

    All subprocess execution goes through this class.
    When *docker_runner* is provided, execution is delegated to
    :meth:`~sailor.infra.docker_runner.DockerRunner.run_asan_replay` so
    the reproducer runs inside the runner container (CLAUDE.md Rule 2).

    Args:
        timeout: Maximum execution time in seconds before the process is
            killed and a :class:`TimeoutError` is raised.
        output_dir: Directory where ``asan_output.txt`` is written.
        docker_runner: When set, delegate execution to this runner instance.
    """

    def __init__(
        self,
        timeout: int = 30,
        output_dir: Path | None = None,
        docker_runner: object | None = None,
    ) -> None:
        self.timeout = timeout
        self.output_dir = output_dir
        self._docker_runner = docker_runner

    def execute(
        self,
        reproducer_path: Path,
        *,
        replay_driver_path: Path | None = None,
        project_archive: Path | None = None,
        include_paths: list[str] | None = None,
    ) -> tuple[bool, str]:
        """Run the reproducer binary and capture output.

        Executes the binary with ``ASAN_OPTIONS=halt_on_error=1:print_stacktrace=1``
        so that ASan stops on the first violation and emits a full stack trace.
        Both stdout and stderr are captured; ASan reports appear on stderr.

        Args:
            reproducer_path: Path to the compiled reproducer binary.

        Returns:
            A ``(crashed, combined_output)`` tuple where *crashed* is ``True``
            if the binary exited abnormally or ASan reported an error.

        Raises:
            TimeoutError: If execution exceeds *timeout* seconds.
        """
        # ── Runner delegation (CLAUDE.md Rule 2) ──────────────────────────
        if self._docker_runner is not None:
            if replay_driver_path is None or project_archive is None:
                raise ValueError(
                    "replay_driver_path and project_archive are required in docker mode."
                )
            driver_c = replay_driver_path.read_text(encoding="utf-8")
            result = self._docker_runner.run_asan_replay(
                replay_driver_c=driver_c,
                asan_archive=str(project_archive),
                include_paths=list(include_paths or []),
            )
            crashed: bool = result.get("crashed", False)
            asan_output: str = result.get("asan_output", "")
            if self.output_dir is not None:
                out_file = self.output_dir / "asan_output.txt"
                out_file.write_text(asan_output, encoding="utf-8")
                logger.debug("Wrote ASan output → %s", out_file)
            logger.info("Runner ASan replay: crashed=%s output_len=%d", crashed, len(asan_output))
            return crashed, asan_output

        # ── Local subprocess fallback ──────────────────────────────────────
        env = {**os.environ, "ASAN_OPTIONS": _ASAN_OPTIONS}
        logger.info("Executing reproducer: %s (timeout=%ds)", reproducer_path, self.timeout)

        try:
            result = subprocess.run(
                [str(reproducer_path)],
                capture_output=True,
                text=True,
                env=env,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Reproducer timed out after %ds.", self.timeout)
            raise TimeoutError(
                f"Reproducer {reproducer_path} exceeded timeout of {self.timeout}s."
            )

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        combined = stdout + stderr
        crashed = self._detect_crash(stdout, stderr, result.returncode)

        if self.output_dir is not None:
            out_file = self.output_dir / "asan_output.txt"
            out_file.write_text(combined, encoding="utf-8")
            logger.debug("Wrote ASan output → %s", out_file)

        logger.info(
            "Reproducer exit_code=%d crashed=%s output_len=%d",
            result.returncode,
            crashed,
            len(combined),
        )
        return crashed, combined

    def _detect_crash(self, stdout: str, stderr: str, exit_code: int) -> bool:
        """Determine whether the execution produced an ASan-detectable crash.

        Args:
            stdout: Captured standard output.
            stderr: Captured standard error.
            exit_code: Process exit code.

        Returns:
            ``True`` if any crash indicator is present.
        """
        if exit_code != 0:
            return True
        if "ERROR: AddressSanitizer" in stderr:
            return True
        if "SUMMARY: AddressSanitizer" in stderr:
            return True
        if "Segmentation fault" in stderr:
            return True
        return False
