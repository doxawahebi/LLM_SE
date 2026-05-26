"""Phase 3 — ASan Compiler.

Compiles unmodified project source with AddressSanitizer instrumentation and
links the replay driver against it to produce a concrete reproducer binary.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from sailor.models.schemas import BuildContext

logger = logging.getLogger("sailor.phase3.asan_compiler")

_EXCLUDE_PATTERNS = frozenset(
    ["test", "tests", "bench", "benchmark", "example", "examples", "fuzz", "fuzzing"]
)


class ASanCompileError(Exception):
    """Raised when ASan compilation or linking fails."""


class ASanCompiler:
    """Compile project source with ASan and link against a replay driver.

    All compilation and archiving go through this class.
    When *docker_runner* is provided, ASan compilation is delegated to
    :meth:`~sailor.infra.docker_runner.DockerRunner.build_asan_archive` so
    all clang calls execute inside the runner container (CLAUDE.md Rule 2).

    Args:
        clang_path: Path to the ``clang`` binary (local fallback).
        project_root: Root directory of the unmodified project source.
        build_context: Compiler flags (include paths, defines) from Phase 1.
        output_dir: Directory where intermediate and final artifacts are written.
        build_command: Shell command used to build the project (e.g. ``make``).
            Required when *docker_runner* is set; ignored otherwise.
        docker_runner: When set, delegate ASan compilation to this runner instance.
    """

    def __init__(
        self,
        clang_path: str,
        project_root: Path,
        build_context: BuildContext,
        output_dir: Path,
        build_command: str = "",
        docker_runner: object | None = None,
    ) -> None:
        self.clang_path = clang_path
        self.project_root = project_root
        self.build_context = build_context
        self.output_dir = output_dir
        self._build_command = build_command
        self._docker_runner = docker_runner

    def compile_project(self) -> Path:
        """Compile unmodified project source with ASan instrumentation.

        Compiles each discovered source file to an object file and bundles all
        object files into a static archive ``project_asan.a``.

        Uses ``compile_commands.json`` when available to obtain per-file
        compiler flags; falls back to scanning ``project_root`` for ``*.c``
        files otherwise.

        Returns:
            Path to the produced ``project_asan.a`` archive.

        Raises:
            ASanCompileError: If any source file fails to compile or archiving
                fails.
        """
        # ── Runner delegation (CLAUDE.md Rule 2) ──────────────────────────
        if self._docker_runner is not None:
            archive_path = self._docker_runner.build_asan_archive(
                project_dir=str(self.project_root),
                build_command=self._build_command,
            )
            logger.info("Runner ASan archive: %s", archive_path)
            return Path(archive_path)

        # ── Local subprocess fallback ──────────────────────────────────────
        source_files = self._get_source_files()
        if not source_files:
            raise ASanCompileError(
                f"No compilable source files found under {self.project_root}"
            )
        logger.info("Compiling %d source files with ASan.", len(source_files))

        obj_dir = self.output_dir / "objects"
        obj_dir.mkdir(parents=True, exist_ok=True)

        include_flags = [f"-I{p}" for p in self.build_context.include_paths]
        define_flags = [f"-D{d}" for d in self.build_context.defines]
        base_flags = [
            self.clang_path,
            "-fsanitize=address",
            "-O1",
            "-g",
            *include_flags,
            *define_flags,
        ]

        obj_files: list[Path] = []
        failed: list[str] = []
        for src in source_files:
            obj_path = obj_dir / (src.stem + "_" + str(abs(hash(str(src)))) + ".o")
            cmd = [*base_flags, "-c", str(src), "-o", str(obj_path)]
            logger.debug("Compiling: %s", " ".join(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.warning(
                    "Compile failed for %s:\n%s", src, result.stderr[:400]
                )
                failed.append(str(src))
            else:
                obj_files.append(obj_path)

        if not obj_files:
            raise ASanCompileError(
                f"All {len(failed)} source files failed to compile. "
                f"First failure: {failed[0]}"
            )
        if failed:
            logger.warning(
                "%d/%d files failed to compile and were skipped.",
                len(failed),
                len(source_files),
            )

        archive_path = self.output_dir / "project_asan.a"
        ar_cmd = ["ar", "rcs", str(archive_path), *[str(o) for o in obj_files]]
        logger.debug("Archiving: %s", " ".join(ar_cmd))
        ar_result = subprocess.run(ar_cmd, capture_output=True, text=True, timeout=60)
        if ar_result.returncode != 0:
            raise ASanCompileError(
                f"ar failed to create {archive_path}:\n{ar_result.stderr}"
            )

        logger.info("Created project archive → %s", archive_path)
        return archive_path

    def compile_replay_driver(
        self, replay_driver_path: Path, project_archive: Path
    ) -> Path:
        """Compile the replay driver and link against the ASan-instrumented project.

        Args:
            replay_driver_path: Path to the ``replay_driver.c`` file.
            project_archive: Path to the ``project_asan.a`` archive.

        Returns:
            Path to the produced ``reproducer`` binary.

        Raises:
            ASanCompileError: If compilation or linking fails.
        """
        reproducer_path = self.output_dir / "reproducer"

        # ── Runner delegation (CLAUDE.md Rule 2) ──────────────────────────
        # In docker mode the replay driver compile+execute is combined in
        # ConcreteExecutor.execute() via runner.run_asan_replay(); return
        # a sentinel path so the pipeline can still call execute() uniformly.
        if self._docker_runner is not None:
            logger.debug("Docker mode: deferring replay driver compile to ConcreteExecutor.")
            return reproducer_path

        # ── Local subprocess fallback ──────────────────────────────────────
        include_flags = [f"-I{p}" for p in self.build_context.include_paths]
        define_flags = [f"-D{d}" for d in self.build_context.defines]
        cmd = [
            self.clang_path,
            "-fsanitize=address",
            "-O1",
            "-g",
            *include_flags,
            *define_flags,
            str(replay_driver_path),
            str(project_archive),
            "-o",
            str(reproducer_path),
        ]
        logger.debug("Linking replay driver: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise ASanCompileError(
                f"Failed to compile/link replay driver:\n{result.stderr}"
            )

        logger.info("Reproducer binary → %s", reproducer_path)
        return reproducer_path

    def _get_source_files(self) -> list[Path]:
        """Collect project source files for compilation.

        Prefers ``compile_commands.json`` when available.  Falls back to
        recursively scanning ``project_root`` for ``*.c`` files, excluding
        directories that typically contain test, benchmark, example, or fuzzing
        code.

        Returns:
            Deduplicated list of absolute paths to source files.
        """
        compile_commands = self.project_root / "compile_commands.json"
        if compile_commands.exists():
            return self._sources_from_compile_commands(compile_commands)
        return self._sources_from_filesystem()

    def _sources_from_compile_commands(self, cc_path: Path) -> list[Path]:
        """Extract source file paths from compile_commands.json.

        Args:
            cc_path: Path to the ``compile_commands.json`` file.

        Returns:
            Deduplicated list of existing ``.c`` source file paths.
        """
        try:
            entries = json.loads(cc_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Could not parse compile_commands.json (%s); falling back to fs scan.",
                exc,
            )
            return self._sources_from_filesystem()

        seen: set[Path] = set()
        sources: list[Path] = []
        for entry in entries:
            file_str = entry.get("file", "")
            p = Path(file_str)
            if not p.is_absolute():
                directory = entry.get("directory", "")
                p = Path(directory) / p
            p = p.resolve()
            if p.suffix == ".c" and p.exists() and p not in seen:
                seen.add(p)
                sources.append(p)
        return sources

    def _sources_from_filesystem(self) -> list[Path]:
        """Recursively find ``*.c`` source files under ``project_root``.

        Excludes directories matching the patterns in ``_EXCLUDE_PATTERNS``
        (test, bench, example, fuzz, etc.).

        Returns:
            List of source file paths sorted for deterministic ordering.
        """
        sources: list[Path] = []
        for p in sorted(self.project_root.rglob("*.c")):
            if any(part.lower() in _EXCLUDE_PATTERNS for part in p.parts):
                continue
            sources.append(p)
        return sources
