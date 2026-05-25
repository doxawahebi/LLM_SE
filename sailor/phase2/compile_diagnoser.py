"""Phase 2 — CompileDiagnoser: compile harness to LLVM bitcode and classify errors."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from sailor.models.schemas import CompileDiagnostic, CompileErrorClass, HarnessArtifacts

logger = logging.getLogger("sailor.phase2.compile_diagnoser")


_DOCKER_IMAGE = "klee/klee"
# klee.h location inside the klee/klee Docker image
_DOCKER_KLEE_INCLUDE = "/tmp/klee_src/include"


class CompileDiagnoser:
    """Compile the harness (driver + slice) to LLVM bitcode via clang.

    All clang and llvm-link invocations go through this class.
    When *docker_runner* is provided, compilation is delegated to
    :meth:`~sailor.infra.docker_runner.DockerRunner.compile_harness` so
    all clang calls execute inside the runner container (CLAUDE.md Rule 2).

    Args:
        clang_path: Path or name of the clang executable (local fallback).
        llvm_link_path: Path or name of the llvm-link executable (local fallback).
        project_root: Absolute path to the C/C++ project source root.
        output_dir: Directory where harness artefacts are written.
        extra_include_paths: Additional -I paths (e.g. project include dirs).
        klee_include_path: Directory containing the klee/ subdirectory with klee.h.
        use_docker: If True, compile inside the klee/klee Docker container so the
            LLVM bitcode version matches the KLEE runtime (local fallback mode).
        docker_runner: When set, delegate all compilation to this runner instance.
    """

    def __init__(
        self,
        clang_path: str,
        llvm_link_path: str,
        project_root: Path,
        output_dir: Path,
        extra_include_paths: list[str] | None = None,
        klee_include_path: str = "",
        use_docker: bool = False,
        docker_runner: object | None = None,
    ) -> None:
        self.clang_path = clang_path
        self.llvm_link_path = llvm_link_path
        self.project_root = Path(project_root)
        self.output_dir = Path(output_dir)
        self._extra_include_paths: list[str] = list(extra_include_paths or [])
        self._klee_include_path = klee_include_path
        self._use_docker = use_docker
        self._docker_runner = docker_runner
        self._harness_dir = self.output_dir / "harness"
        self._harness_dir.mkdir(parents=True, exist_ok=True)

    def compile(
        self, driver_c: str, slice_c: str
    ) -> tuple[bool, CompileDiagnostic | None]:
        """Compile driver and slice to linked LLVM bitcode.

        When *docker_runner* was supplied at construction time, delegates to
        :meth:`~sailor.infra.docker_runner.DockerRunner.compile_harness` so
        that clang runs inside the runner container.

        Args:
            driver_c: Full C source of the driver (contains ``main()``).
            slice_c: Full C source of the code slice and stubs.

        Returns:
            ``(True, None)`` on success.
            ``(False, CompileDiagnostic)`` on compilation failure.
        """
        # ── Runner delegation (CLAUDE.md Rule 2) ──────────────────────────
        if self._docker_runner is not None:
            success, stderr = self._docker_runner.compile_harness(
                driver_c=driver_c,
                slice_c=slice_c,
                include_paths=[_DOCKER_KLEE_INCLUDE] + self._extra_include_paths,
            )
            if not success:
                diag = self._classify_error(stderr)
                logger.warning(
                    "Runner compile failed [%s]: %s",
                    diag.error_class,
                    stderr[:200],
                )
                return False, diag
            # Update harness.bc path (container writes via shared volume)
            harness_bc = self._harness_dir / "harness.bc"
            return True, None

        # ── Local subprocess fallback ──────────────────────────────────────
        driver_path = self._harness_dir / "driver.c"
        slice_path = self._harness_dir / "slice.c"
        driver_bc = self._harness_dir / "driver.bc"
        slice_bc = self._harness_dir / "slice.bc"
        harness_bc = self._harness_dir / "harness.bc"

        driver_path.write_text(driver_c, encoding="utf-8")
        slice_path.write_text(slice_c, encoding="utf-8")

        # When using Docker, klee.h lives inside the container; use its known path.
        klee_inc = _DOCKER_KLEE_INCLUDE if self._use_docker else self._klee_include_path

        include_flags: list[str] = []
        if klee_inc:
            include_flags += ["-I", klee_inc]
        for p in self._extra_include_paths:
            include_flags += ["-I", p]

        base_flags = [
            "-O0", "-g",
            "-emit-llvm", "-c",
            "-Xclang", "-disable-O0-optnone",
            *include_flags,
        ]

        # Compile driver
        ok, diag = self._compile_one(driver_path, driver_bc, base_flags)
        if not ok:
            return False, diag

        # Compile slice
        ok, diag = self._compile_one(slice_path, slice_bc, base_flags)
        if not ok:
            return False, diag

        # Link
        link_cmd = self._build_link_cmd(str(driver_bc), str(slice_bc), str(harness_bc))
        logger.debug("llvm-link: %s", " ".join(link_cmd))
        link_result = subprocess.run(link_cmd, capture_output=True, text=True, timeout=60)
        if link_result.returncode != 0:
            stderr = (link_result.stderr or "") + (link_result.stdout or "")
            diag = self._classify_error(stderr)
            logger.warning("Link failed [%s]: %s", diag.error_class, stderr[:200])
            return False, diag

        logger.info("Compiled harness.bc at %s", harness_bc)
        return True, None

    def get_harness_bc_path(self) -> str:
        """Return the path to the compiled harness.bc."""
        return str(self._harness_dir / "harness.bc")

    def get_compile_cmd(self, source_file: str, output_file: str) -> str:
        """Return the clang compile command string for recording in artefacts."""
        return (
            f"{self.clang_path} -O0 -g -emit-llvm -c "
            f"-Xclang -disable-O0-optnone {source_file} -o {output_file}"
        )

    def get_link_cmd(self, driver_bc: str, slice_bc: str, harness_bc: str) -> str:
        """Return the llvm-link command string for recording in artefacts."""
        return f"{self.llvm_link_path} {driver_bc} {slice_bc} -o {harness_bc}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _docker_prefix(self, work_dir: str) -> list[str]:
        """Build the docker run prefix that mounts host paths into the container."""
        mounts = [
            "-v", f"{work_dir}:{work_dir}",
            "-v", f"{self.project_root}:{self.project_root}",
        ]
        return [
            "docker", "run", "--rm",
            *mounts,
            "-w", work_dir,
            _DOCKER_IMAGE,
        ]

    def _build_link_cmd(self, driver_bc: str, slice_bc: str, harness_bc: str) -> list[str]:
        """Build the llvm-link command, optionally wrapped in Docker."""
        # Inside the klee/klee container the tool is simply "llvm-link" (no version suffix).
        link_bin = "llvm-link" if self._use_docker else self.llvm_link_path
        link_args = [link_bin, driver_bc, slice_bc, "-o", harness_bc]
        if self._use_docker:
            work_dir = str(Path(harness_bc).parent)
            return self._docker_prefix(work_dir) + link_args
        return link_args

    def _compile_one(
        self,
        src: Path,
        out: Path,
        base_flags: list[str],
    ) -> tuple[bool, CompileDiagnostic | None]:
        """Compile a single C file to LLVM bitcode."""
        # Inside the klee/klee container the compiler is simply "clang" (no version suffix).
        clang_bin = "clang" if self._use_docker else self.clang_path
        compile_args = [clang_bin] + base_flags + [str(src), "-o", str(out)]
        if self._use_docker:
            work_dir = str(src.parent)
            cmd = self._docker_prefix(work_dir) + compile_args
        else:
            cmd = compile_args
        logger.debug("clang: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            return False, CompileDiagnostic(
                error_class=CompileErrorClass.OTHER,
                raw_error="clang timed out after 120 seconds.",
                suggested_fix="Simplify the harness source.",
            )
        if result.returncode != 0:
            stderr = (result.stderr or "") + (result.stdout or "")
            diag = self._classify_error(stderr)
            logger.warning(
                "Compile failed [%s] %s: %s",
                diag.error_class,
                src.name,
                stderr[:200],
            )
            return False, diag
        return True, None

    def _classify_error(self, stderr: str) -> CompileDiagnostic:
        """Classify a clang/llvm-link error into one of four categories.

        Args:
            stderr: Raw compiler error output.

        Returns:
            A populated :class:`CompileDiagnostic`.
        """
        # incomplete_type
        if re.search(r"incomplete type|has no member named|unknown type name", stderr, re.I):
            type_match = re.search(r"'(\w+)'.*incomplete type|unknown type name '(\w+)'", stderr)
            type_name = (type_match.group(1) or type_match.group(2)) if type_match else None
            relevant = self._grep_header(type_name) if type_name else None
            return CompileDiagnostic(
                error_class=CompileErrorClass.INCOMPLETE_TYPE,
                raw_error=stderr[:2000],
                suggested_fix=(
                    f"Add a forward declaration or minimal typedef for '{type_name}' "
                    "to the slice file. Do NOT #include project headers."
                ),
                relevant_source=relevant,
            )

        # conflicting_prototype
        if re.search(r"conflicting types for|redeclared as different kind", stderr, re.I):
            func_match = re.search(r"conflicting types for '(\w+)'", stderr)
            func_name = func_match.group(1) if func_match else None
            relevant = self._grep_prototype(func_name) if func_name else None
            return CompileDiagnostic(
                error_class=CompileErrorClass.CONFLICTING_PROTO,
                raw_error=stderr[:2000],
                suggested_fix=(
                    f"Change the stub signature for '{func_name}' to match: "
                    f"{relevant or 'check project headers'}"
                ),
                relevant_source=relevant,
            )

        # redefinition
        if re.search(r"redefinition of|previously defined", stderr, re.I):
            return CompileDiagnostic(
                error_class=CompileErrorClass.REDEFINITION,
                raw_error=stderr[:2000],
                suggested_fix=(
                    "Add #ifndef guards around the redefined symbol "
                    "or remove the duplicate definition."
                ),
            )

        # other
        return CompileDiagnostic(
            error_class=CompileErrorClass.OTHER,
            raw_error=stderr[:2000],
            suggested_fix="Fix the syntax error shown above.",
        )

    def _grep_header(self, type_name: str) -> str | None:
        """Grep project headers for a type definition."""
        try:
            result = subprocess.run(
                [
                    "grep", "-rn", type_name,
                    "--include=*.h",
                    str(self.project_root),
                ],
                capture_output=True, text=True, timeout=15,
            )
            lines = result.stdout.strip().splitlines()
            return "\n".join(lines[:5]) if lines else None
        except (subprocess.TimeoutExpired, OSError):
            return None

    def _grep_prototype(self, func_name: str) -> str | None:
        """Grep project headers for a function prototype."""
        try:
            result = subprocess.run(
                [
                    "grep", "-rn", rf"\b{func_name}\b",
                    "--include=*.h",
                    str(self.project_root),
                ],
                capture_output=True, text=True, timeout=15,
            )
            lines = result.stdout.strip().splitlines()
            return "\n".join(lines[:3]) if lines else None
        except (subprocess.TimeoutExpired, OSError):
            return None
