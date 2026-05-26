"""DockerRunner: executes all Phase operations inside an ephemeral container.

The local machine never runs codeql, klee, clang, make, or git clone.
All Phase 1/2/3 commands are dispatched via ``docker exec`` into a
per-CVE runner container built from ``docker/Dockerfile.runner``.

Usage pattern (all callers must use a finally block):

    runner = DockerRunner(cve_id="CVE-2025-11494", config=RunnerConfig())
    try:
        runner.start()
        runner.setup_target(...)
        sarif = runner.run_phase1(...)
    finally:
        runner.stop()   # ALWAYS — Rule 3 in CLAUDE.md
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("sailor.infra.docker_runner")


def _default_network() -> str:
    return os.environ.get("RUNNER_NETWORK", "sailor_net")


@dataclass
class RunnerConfig:
    """Configuration for a DockerRunner instance.

    Attributes:
        image: Docker image name for the runner container.
        workspace_base: Container-side path for workspace files (worker view).
        output_base: Container-side path for output files (worker view).
        workspace_volume: Named Docker volume for workspace (used in runner mount).
            When set, runner is started with ``-v <name>:/workspace`` instead of
            a bind-mount from ``workspace_base``.  Required when the worker itself
            runs inside Docker because the host path for named volumes is not
            accessible via a bind-mount.
        output_volume: Named Docker volume for output (used in runner mount).
        network: Docker network the runner container joins.
        cpu_limit: ``--cpus`` flag value for the container.
        memory_limit: ``--memory`` flag value for the container.
        build_timeout: Seconds allowed for target clone + build.
        codeql_timeout: Seconds allowed for a full CodeQL database + analysis run.
        klee_timeout_per_run: Per-run KLEE wall-clock limit (paper: T_klee=300s).
        asan_timeout: Seconds allowed for ASan reproducer execution.
    """

    image: str = field(default_factory=lambda: os.environ.get("RUNNER_IMAGE", "sailor-runner:latest"))
    workspace_base: Path = field(default_factory=lambda: Path(os.environ.get("WORKSPACE_BASE", "/data/workspace")))
    output_base: Path = field(default_factory=lambda: Path(os.environ.get("OUTPUT_BASE", "/data/output")))
    # Named volume names — set these when running inside Docker so the runner
    # container shares the same named volumes instead of a host bind-mount.
    workspace_volume: str = field(default_factory=lambda: os.environ.get("WORKSPACE_VOLUME", ""))
    output_volume: str = field(default_factory=lambda: os.environ.get("OUTPUT_VOLUME", ""))
    network: str = field(default_factory=_default_network)
    cpu_limit: str = "4"
    memory_limit: str = "8g"
    build_timeout: int = 1800
    codeql_timeout: int = 3600
    klee_timeout_per_run: int = 300  # Paper §4: T_klee = 300s
    asan_timeout: int = 60

    def __post_init__(self) -> None:
        self.workspace_base = Path(self.workspace_base)
        self.output_base = Path(self.output_base)


class DockerRunner:
    """Manage an ephemeral Docker container for one CVE evaluation.

    One ``DockerRunner`` instance corresponds to one container and one CVE.
    All Phase 1/2/3 operations execute INSIDE the container via
    :meth:`exec`.  Results are written to a shared volume and collected
    as JSON by the caller.

    Callers MUST call :meth:`stop` in a ``finally`` block to ensure the
    container is removed even when an exception occurs.

    Args:
        cve_id: CVE identifier (used as the container name suffix).
        config: Runner configuration.
    """

    def __init__(self, cve_id: str, config: RunnerConfig) -> None:
        self.cve_id = cve_id
        self.config = config
        self.container_id: str | None = None
        self.workspace: Path = config.workspace_base / cve_id
        self.output_dir: Path = config.output_base / cve_id

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the runner container.

        Mounts ``workspace_base`` and ``output_base`` as volumes and keeps
        the container alive with ``sleep infinity``.  Actual work is
        dispatched via :meth:`exec`.

        Raises:
            RuntimeError: If the ``docker run`` command fails.
        """
        # Use named volume mounts when running inside Docker (worker context);
        # fall back to bind-mounts for local execution.
        ws_mount = (
            f"{self.config.workspace_volume}:/workspace"
            if self.config.workspace_volume
            else f"{self.config.workspace_base}:/workspace"
        )
        out_mount = (
            f"{self.config.output_volume}:/output"
            if self.config.output_volume
            else f"{self.config.output_base}:/output"
        )
        cmd = [
            "docker", "run", "-d",
            "--name", f"sailor-runner-{self.cve_id}",
            "--network", self.config.network,
            "--cpus", self.config.cpu_limit,
            "--memory", self.config.memory_limit,
            "-v", ws_mount,
            "-v", out_mount,
            "-e", f"CVE_ID={self.cve_id}",
            self.config.image,
            "sleep", "infinity",
        ]
        result = self._local_run(cmd)
        self.container_id = result.stdout.strip()
        log.info("[%s] Container started: %s", self.cve_id, self.container_id[:12])

    def stop(self) -> None:
        """Stop and remove the container.

        Safe to call even if :meth:`start` was never called or already
        raised.  Always call this in a ``finally`` block.
        """
        if self.container_id:
            self._local_run(
                ["docker", "rm", "-f", self.container_id],
                check=False,
            )
            log.info("[%s] Container removed.", self.cve_id)
            self.container_id = None

    # ── Target Setup ──────────────────────────────────────────────────────

    def setup_target(
        self,
        project_url: str | None,
        commit: str | None,
        build_commands: list[str],
        dependencies: list[str],
        local_source_path: str | None = None,
    ) -> Path:
        """Clone or copy the target project into the container, then build it.

        Exactly one of *project_url* or *local_source_path* must be provided.

        Args:
            project_url: Git remote URL of the target project (exclusive with
                *local_source_path*).
            commit: Git commit hash to check out (required when *project_url*
                is set).
            build_commands: Shell commands to run (in order) to build the project.
            dependencies: Packages to ``apt-get install`` before building.
            local_source_path: Host-side path to copy into the container via
                ``docker cp`` (exclusive with *project_url*).

        Returns:
            Path to the project root *inside the container*.

        Raises:
            ValueError: If both or neither of *project_url* / *local_source_path*
                are provided.
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
        """Copy a local directory into the container's workspace.

        Used by e2e tests where the target is a local C file, not a git repo.

        Args:
            local_path: Host-side directory path to copy (all contents are
                copied, not the directory itself).

        Returns:
            Absolute path inside the container where the source was placed.

        Raises:
            RuntimeError: If the ``docker cp`` command fails.
        """
        container_path = f"/workspace/{self.cve_id}/src"
        self.exec(f"mkdir -p {container_path}")
        result = self._local_run(
            [
                "docker", "cp",
                f"{local_path}/.",
                f"{self.container_id}:{container_path}",
            ],
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"[{self.cve_id}] docker cp failed: {result.stderr}"
            )
        log.info("[%s] Copied local source %s → %s", self.cve_id, local_path, container_path)
        return container_path

    # ── Phase 1 ───────────────────────────────────────────────────────────

    def run_phase1(
        self,
        project_dir: str,
        build_command: str | None = None,
        build_mode: str | None = None,
    ) -> dict[str, Any]:
        """Build a CodeQL database and run the query suite inside the container.

        Args:
            project_dir: Absolute path to the project root *inside the container*.
            build_command: The build command CodeQL should intercept (e.g. ``make``).
                Mutually exclusive with *build_mode*.
            build_mode: CodeQL build mode (e.g. ``autobuild``, ``manual``).
                Used when no explicit *build_command* is provided.

        Returns:
            Parsed SARIF dict read from the shared output volume.

        Raises:
            RuntimeError: If CodeQL fails.
        """
        db_path = f"/workspace/{self.cve_id}/codeql_db"
        sarif_path = f"/output/{self.cve_id}/findings.sarif"

        if build_command:
            build_arg = f"--command='{build_command}'"
        else:
            mode = build_mode if build_mode and build_mode not in ("autodetect", "none", "") else "autobuild"
            build_arg = f"--build-mode={mode}"

        self.exec(
            f"codeql database create {db_path} "
            f"--language=cpp "
            f"{build_arg} "
            f"--source-root={project_dir} "
            f"--overwrite",
            cwd=project_dir,
            timeout=self.config.codeql_timeout,
        )
        # Write custom .ql queries to the shared workspace volume so the runner
        # can access them at /workspace/{cve_id}/cql_queries/.
        custom_queries_host = self.config.workspace_base / self.cve_id / "cql_queries"
        custom_queries_container = f"/workspace/{self.cve_id}/cql_queries"
        try:
            from sailor.codeql.queries import CodeQLQuerySuite
            suite = CodeQLQuerySuite()
            suite.write_custom_queries(custom_queries_host)
            log.info("[%s] Wrote %d custom queries to %s",
                     self.cve_id, len(list(custom_queries_host.glob("*.ql"))), custom_queries_host)
        except Exception as exc:
            log.warning("[%s] Could not write custom queries: %s", self.cve_id, exc)
            custom_queries_container = None

        # Ensure output directory exists inside the container before analyze writes SARIF.
        sarif_dir = f"/output/{self.cve_id}"
        self.exec(f"mkdir -p {sarif_dir}")

        # Use the built-in C++ security query suite plus our custom queries.
        analyze_targets = "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls"
        if custom_queries_container:
            analyze_targets += f" {custom_queries_container}"
        self.exec(
            f"codeql database analyze {db_path} "
            f"{analyze_targets} "
            f"--format=sarifv2.1.0 "
            f"--output={sarif_path}",
            timeout=self.config.codeql_timeout,
        )

        host_sarif = self.config.output_base / self.cve_id / "findings.sarif"
        return json.loads(host_sarif.read_text(encoding="utf-8"))

    # ── Phase 2 ───────────────────────────────────────────────────────────

    def compile_harness(
        self,
        driver_c: str,
        slice_c: str,
        include_paths: list[str],
    ) -> tuple[bool, str]:
        """Compile driver + slice to LLVM bitcode inside the container.

        Copies the C sources into the container via ``docker cp`` (instead of
        writing to the shared volume path, which may be root-owned when Docker
        created it via ``exec mkdir``).  The compiled ``.bc`` artifacts remain
        inside the container; callers only read the ``klee-out-*`` directory.

        Args:
            driver_c: Full C source of the driver (contains ``main()``).
            slice_c: Full C source of the code slice and stubs.
            include_paths: ``-I<path>`` flags (as bare path strings).

        Returns:
            ``(True, "")`` on success.
            ``(False, stderr)`` on compilation or link failure.
        """
        import tempfile

        harness_dir = f"/workspace/{self.cve_id}/harness"
        self.exec(f"mkdir -p {harness_dir}")

        # Write to a user-owned temp dir and copy into the container so we
        # never need to write to a volume path that Docker (root) may own.
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "driver.c").write_text(driver_c, encoding="utf-8")
            (tmp / "slice.c").write_text(slice_c, encoding="utf-8")
            cp_result = self._local_run(
                ["docker", "cp", f"{tmpdir}/.", f"{self.container_id}:{harness_dir}"],
                check=False,
            )
            if cp_result.returncode != 0:
                return False, f"docker cp harness files failed: {cp_result.stderr}"

        includes = " ".join(f"-I{p}" for p in include_paths) if include_paths else ""

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

        link_r = self.exec(
            f"llvm-link {harness_dir}/driver.bc {harness_dir}/slice.bc "
            f"-o {harness_dir}/harness.bc",
            check=False,
        )
        if link_r["exit_code"] != 0:
            return False, link_r["stderr"]

        return True, ""

    def run_klee(self, spec_id: str) -> dict[str, Any]:
        """Run KLEE on the compiled harness inside the container.

        Uses the paper settings: dual-strategy (random-path + DFS),
        T_klee=300s, depth=1000.

        Args:
            spec_id: Identifier used to name the KLEE output directory
                (``klee-out-<spec_id>``).

        Returns:
            Dict with keys:
            - ``outcome``: ``"bug_triggered"`` | ``"site_reached"`` | ``"not_reached"``
            - ``ktest_paths``: list of ``.ktest`` file paths (host-side)
            - ``stderr``: raw KLEE stderr
            - ``probes_entered``: list of function names where SPINE_PROBE fired
        """
        harness_bc = f"/workspace/{self.cve_id}/harness/harness.bc"
        klee_out = f"/workspace/{self.cve_id}/klee-out-{spec_id}"

        # Remove stale output dir so KLEE doesn't fail with "File exists"
        self.exec(f"rm -rf {klee_out}", check=False)

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

        host_klee_out = (
            self.config.workspace_base / self.cve_id / f"klee-out-{spec_id}"
        )
        ktest_paths: list[str] = []
        real_error_files: list[Path] = []
        assert_err_files: list[Path] = []
        if host_klee_out.exists():
            ktest_paths = sorted(str(p) for p in host_klee_out.glob("*.ktest"))
            # Check .err files directly — more reliable than parsing stderr text.
            # ptr.err / free.err / null.err etc. = real memory safety errors (BUG_TRIGGERED)
            # assert.err = reachability assertion fired (SITE_REACHED)
            real_error_files = [
                p for p in host_klee_out.glob("*.err")
                if not p.name.endswith(".assert.err")
            ]
            assert_err_files = list(host_klee_out.glob("*.assert.err"))

        # Fallback: stderr-based detection (handles cases where volume path lags)
        real_error_stderr = (
            "memory error" in stderr.lower()
            or "invalid memory access" in stderr.lower()
        )
        sailor_assert_stderr = "SAILOR_SINK_REACHED" in stderr

        if (real_error_files or real_error_stderr) and ktest_paths:
            outcome = "bug_triggered"
        elif (assert_err_files or sailor_assert_stderr) and ktest_paths:
            outcome = "site_reached"
        else:
            outcome = "not_reached"

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

    # ── Phase 3 ───────────────────────────────────────────────────────────

    def build_asan_archive(self, project_dir: str, build_command: str | None = None) -> str:
        """Rebuild the UNMODIFIED project with ASan inside the container.

        Packages all resulting ``.o`` files into a static archive.

        Args:
            project_dir: Absolute path to the project root *inside the container*.
            build_command: Build command that produces object files.  When
                ``None``, auto-detects: ``make`` if a Makefile is present,
                ``cmake --build .`` if CMakeLists.txt is present.

        Returns:
            Absolute path (container-side) to the produced ``project_asan.a``
            archive.
        """
        if build_command is None:
            probe = self.exec(
                f"test -f {project_dir}/Makefile && echo make "
                f"|| (test -f {project_dir}/CMakeLists.txt && echo cmake) "
                f"|| echo make",
                check=False,
            )
            detected = (probe.get("stdout") or "make").strip().split("\n")[0].strip()
            build_command = detected if detected else "make"

        asan_dir = f"/workspace/{self.cve_id}/asan-build"
        self.exec(f"mkdir -p {asan_dir}")

        # Clean stale object files so make re-compiles with ASan flags
        if build_command.startswith("make"):
            self.exec(
                f"{build_command} clean 2>/dev/null || true",
                cwd=project_dir,
                check=False,
            )

        self.exec(
            f"CFLAGS='-fsanitize=address -O1 -g' "
            f"CXXFLAGS='-fsanitize=address -O1 -g' "
            f"LDFLAGS='-fsanitize=address' "
            f"{build_command}",
            cwd=project_dir,
            timeout=self.config.build_timeout,
        )

        archive_path = f"{asan_dir}/project_asan.a"
        self.exec(
            f"find {project_dir} -name '*.o' | xargs ar rcs {archive_path}"
        )
        return archive_path

    def run_asan_replay(
        self,
        replay_driver_c: str,
        asan_archive: str,
        include_paths: list[str],
        project_dir: str | None = None,
    ) -> dict[str, Any]:
        """Compile a replay driver against the project source and execute it.

        When *project_dir* is provided (preferred), all project ``.c`` files are
        compiled together with the replay driver in a single translation unit so
        that ``static`` functions remain visible.  When *project_dir* is absent
        the legacy archive-linking path is used.

        Args:
            replay_driver_c: C source of the replay driver.
            asan_archive: Container-side path to the ASan-instrumented archive
                (used as fallback only).
            include_paths: ``-I<path>`` flags (as bare path strings).
            project_dir: Absolute path inside the container to the project root
                whose ``.c`` files should be compiled alongside the driver.

        Returns:
            Dict with keys:
            - ``crashed``: ``True`` if the binary crashed or ASan reported an error.
            - ``asan_output``: Combined stdout + stderr from the reproducer.
            - ``error`` (optional): ``"compile_failed"`` if compilation failed.
        """
        import re
        import tempfile

        replay_dir = f"/workspace/{self.cve_id}/replay"
        self.exec(f"mkdir -p {replay_dir}")

        if project_dir:
            # ── Inline (single-TU) compilation ──────────────────────────────
            # Find all project .c files; exclude any generated replay_driver.c
            find_r = self.exec(
                f"find {project_dir} -maxdepth 3 -name '*.c'"
                f" -not -name 'replay_driver.c' 2>/dev/null",
                check=False,
            )
            proj_c_files = sorted(
                line.strip()
                for line in find_r["stdout"].splitlines()
                if line.strip()
            )

            # Build a combined source: project files (main renamed) + replay driver
            header_lines = [
                "#include <string.h>",
                "#include <stdlib.h>",
                "#include <stddef.h>",
            ]
            proj_sections: list[str] = []
            for i, cf in enumerate(proj_c_files):
                cat_r = self.exec(f"cat {cf}", check=False)
                content = cat_r["stdout"]
                proj_sections.append(
                    f"/* ==== {cf} ==== */\n"
                    f"#define main __proj_main_{i}__\n"
                    f"{content}\n"
                    f"#undef main\n"
                )

            # Remove forward declarations from replay driver that would conflict
            # with definitions now visible in the same TU.
            replay_clean = re.sub(
                r"^\s*(?:static\s+|extern\s+)?[a-zA-Z_][a-zA-Z0-9_ *]*\s+"
                r"\w+\s*\([^)]*\)\s*;\s*$",
                "",
                replay_driver_c,
                flags=re.MULTILINE,
            )
            # Remove duplicate standard includes from replay driver
            replay_clean = re.sub(
                r"#\s*include\s*[<\"](string|stdlib|stddef)\.h[>\"]\s*\n?",
                "",
                replay_clean,
            )

            combined = "\n".join(header_lines) + "\n" + "\n".join(proj_sections) + "\n" + replay_clean
            combined_path = f"{replay_dir}/combined.c"

            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                (tmp / "combined.c").write_text(combined, encoding="utf-8")
                cp_result = self._local_run(
                    ["docker", "cp",
                     f"{tmpdir}/.", f"{self.container_id}:{replay_dir}"],
                    check=False,
                )
                if cp_result.returncode != 0:
                    return {
                        "crashed": False,
                        "asan_output": f"docker cp combined.c failed: {cp_result.stderr}",
                        "error": "compile_failed",
                    }

            includes = " ".join(f"-I{p}" for p in include_paths) if include_paths else ""
            compile_r = self.exec(
                f"clang -fsanitize=address -O0 -g "
                f"-fno-optimize-sibling-calls -fno-omit-frame-pointer "
                f"{includes} "
                f"{combined_path} "
                f"-o {replay_dir}/reproducer",
                check=False,
            )
        else:
            # ── Legacy archive-linking path ──────────────────────────────────
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                (tmp / "replay_driver.c").write_text(replay_driver_c, encoding="utf-8")
                cp_result = self._local_run(
                    ["docker", "cp",
                     f"{tmpdir}/.", f"{self.container_id}:{replay_dir}"],
                    check=False,
                )
                if cp_result.returncode != 0:
                    return {
                        "crashed": False,
                        "asan_output": f"docker cp replay_driver failed: {cp_result.stderr}",
                        "error": "compile_failed",
                    }

            includes = " ".join(f"-I{p}" for p in include_paths) if include_paths else ""
            compile_r = self.exec(
                f"clang -fsanitize=address -O1 -g "
                f"{includes} "
                f"{replay_dir}/replay_driver.c "
                f"{asan_archive} "
                f"-o {replay_dir}/reproducer",
                check=False,
            )

        if compile_r["exit_code"] != 0:
            return {
                "crashed": False,
                "asan_output": compile_r["stderr"],
                "error": "compile_failed",
            }

        run_r = self.exec(
            f"ASAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "
            f"{replay_dir}/reproducer",
            timeout=self.config.asan_timeout,
            check=False,
        )
        asan_output = run_r["stdout"] + run_r["stderr"]
        crashed = (
            run_r["exit_code"] != 0
            or "ERROR: AddressSanitizer" in asan_output
        )
        return {"crashed": crashed, "asan_output": asan_output}

    # ── Internal exec ─────────────────────────────────────────────────────

    def exec(
        self,
        command: str,
        cwd: str | None = None,
        timeout: int = 300,
        check: bool = True,
    ) -> dict[str, Any]:
        """Run a shell command INSIDE the container via ``docker exec``.

        All Phase 1/2/3 commands go through this method.
        Never executes anything on the local machine.

        Args:
            command: Shell command string to run inside the container.
            cwd: Working directory inside the container (optional).
            timeout: Maximum wall-clock time in seconds.
            check: If ``True``, raise :class:`RuntimeError` on non-zero exit.

        Returns:
            Dict with keys ``exit_code``, ``stdout``, ``stderr``.

        Raises:
            RuntimeError: If the container is not started, or if *check* is
                ``True`` and the command exits non-zero.
            TimeoutError: If the command exceeds *timeout*.
        """
        if not self.container_id:
            raise RuntimeError(
                f"[{self.cve_id}] Container not started. Call start() first."
            )

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
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"[{self.cve_id}] Command timed out ({timeout}s): {command[:80]}"
            ) from exc

        log.debug(
            "[%s] exec exit=%d: %s",
            self.cve_id,
            result.returncode,
            command[:60],
        )

        if check and result.returncode != 0:
            raise RuntimeError(
                f"[{self.cve_id}] Command failed (exit {result.returncode}):\n"
                f"  cmd:    {command[:120]}\n"
                f"  stderr: {result.stderr[:500]}"
            )

        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def _local_run(
        self,
        cmd: list[str],
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a command on the LOCAL machine (Docker CLI calls only).

        Args:
            cmd: Command + arguments list.
            check: If ``True``, raise :class:`subprocess.CalledProcessError`
                on non-zero exit.

        Returns:
            Completed process result.
        """
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )
