"""CodeQL CLI wrapper — the single authoritative interface to CodeQL in this project.

**Design contract**: Every interaction with the ``codeql`` executable MUST go through
:class:`CodeQLRunner`.  Direct ``subprocess`` calls to ``codeql`` anywhere else in the
codebase are explicitly forbidden so that timeout handling, error normalisation, and
logging remain consistent across the entire pipeline.

Typical usage::

    from pathlib import Path
    from codeql.wrapper import CodeQLRunner, CodeQLError

    runner = CodeQLRunner(codeql_path="/usr/local/bin/codeql", db_path=Path("/tmp/mydb"))
    version = runner.check_installation()
    db = runner.create_database(source_root=Path("/src/myproject"))
    sarif = runner.run_query(query_path=Path("/ql/my_query.ql"),
                             output_path=Path("/tmp/out.sarif"))
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class CodeQLError(Exception):
    """Raised when the CodeQL CLI exits with a non-zero return code.

    Attributes:
        returncode: The exit code returned by the CodeQL process.
        stderr: The captured standard-error output from the process.
        command: The full command that was executed (redacted list of strings).
    """

    def __init__(
        self,
        message: str,
        *,
        returncode: int,
        stderr: str,
        command: list[str],
    ) -> None:
        """Initialise a :class:`CodeQLError`.

        Args:
            message: Human-readable summary of the failure.
            returncode: Exit code from the CodeQL subprocess.
            stderr: Captured stderr text from the CodeQL subprocess.
            command: The command list that was executed.
        """
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
        self.command = command

    def __str__(self) -> str:
        cmd_str = " ".join(self.command)
        return (
            f"{super().__str__()}\n"
            f"  command   : {cmd_str}\n"
            f"  exit code : {self.returncode}\n"
            f"  stderr    :\n{self.stderr}"
        )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class CodeQLRunner:
    """Object-oriented abstraction over the CodeQL CLI.

    All CodeQL CLI calls in the project MUST go through this class.
    Direct subprocess calls to ``codeql`` are forbidden elsewhere.

    Attributes:
        codeql_path: Absolute path (or bare name on ``$PATH``) for the
            ``codeql`` executable.
        db_path: Path to the CodeQL database to query or build.
        timeout: Maximum seconds to wait for any single CLI invocation.
    """

    def __init__(
        self,
        codeql_path: str,
        db_path: Path,
        timeout: int = 3600,
    ) -> None:
        """Initialise a :class:`CodeQLRunner`.

        Args:
            codeql_path: Path or name of the ``codeql`` executable.  If a bare
                name is given (e.g. ``"codeql"``), it must be resolvable via
                ``$PATH``.
            db_path: Path to the CodeQL database directory.
            timeout: Maximum wall-clock seconds for any single CLI invocation.
                Defaults to 3600 (one hour).

        Raises:
            ValueError: If *codeql_path* is empty or *timeout* is not positive.
        """
        if not codeql_path or not codeql_path.strip():
            raise ValueError("codeql_path must not be empty.")
        if timeout <= 0:
            raise ValueError(f"timeout must be a positive integer, got {timeout!r}.")

        self.codeql_path: str = codeql_path.strip()
        self.db_path: Path = Path(db_path)
        self.timeout: int = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_installation(self) -> str:
        """Verify that the CodeQL CLI is available and return its version string.

        Runs ``codeql --version`` and parses the first non-empty output line.

        Returns:
            The version string reported by the CLI, e.g.
            ``'CodeQL command-line toolchain release 2.17.0'``.

        Raises:
            CodeQLError: If the executable is not found, cannot be executed,
                or exits with a non-zero return code.
        """
        result = self._run(["--version"])
        # codeql --version prints multiple lines; the first non-empty line
        # contains the version banner.
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped:
                logger.info("CodeQL installation verified: %s", stripped)
                return stripped
        # Fallback: return all stdout (should not happen with a valid binary).
        return result.stdout.strip()

    def create_database(
        self,
        source_root: Path,
        build_command: str | None = None,
        language: str = "cpp",
        overwrite: bool = True,
    ) -> Path:
        """Build a CodeQL database from a C/C++ source tree.

        Selects the appropriate build strategy automatically:

        * If ``compile_commands.json`` is present at *source_root*, the database
          is created with ``--build-mode=none`` (compilation-database mode).
        * Otherwise, *build_command* is used with ``--command=<build_command>``.
          A ``ValueError`` is raised if *build_command* is also absent.

        Args:
            source_root: Root directory of the source tree to analyse.
            build_command: Shell command used to build the project (e.g.
                ``"make -j4"``).  Required when no ``compile_commands.json``
                is found.
            language: CodeQL language extractor to use.  Defaults to ``"cpp"``.
            overwrite: When ``True``, pass ``--overwrite`` so an existing
                database at :attr:`db_path` is replaced.  Defaults to ``True``.

        Returns:
            The (possibly newly created) :attr:`db_path`.

        Raises:
            FileNotFoundError: If *source_root* does not exist.
            ValueError: If no ``compile_commands.json`` is found and
                *build_command* is ``None``.
            CodeQLError: If the ``codeql database create`` command fails.
        """
        source_root = Path(source_root).resolve()
        if not source_root.is_dir():
            raise FileNotFoundError(
                f"source_root does not exist or is not a directory: {source_root}"
            )

        compile_commands = source_root / "compile_commands.json"
        use_compilation_db = compile_commands.is_file()

        if not use_compilation_db and build_command is None:
            raise ValueError(
                "No compile_commands.json found at source_root and build_command "
                "is None.  Provide one of the two so CodeQL can extract the build."
            )

        args: list[str] = [
            "database",
            "create",
            str(self.db_path),
            f"--language={language}",
            f"--source-root={source_root}",
        ]

        if use_compilation_db:
            args.append("--build-mode=none")
            logger.info(
                "Using compilation-database mode (compile_commands.json found at %s).",
                source_root,
            )
        else:
            # build_command is guaranteed non-None here.
            args.append(f"--command={build_command}")
            logger.info("Using build-command mode: %s", build_command)

        if overwrite:
            args.append("--overwrite")

        self._run(args)
        logger.info("CodeQL database created at %s.", self.db_path)
        return self.db_path

    def run_query(
        self,
        query_path: Path,
        output_path: Path,
        format: str = "sarifv2.1.0",
    ) -> dict[str, Any]:
        """Run a single ``.ql`` query against :attr:`db_path`.

        The query is compiled and evaluated in a single ``codeql database analyze``
        invocation.  The SARIF output is written to *output_path* and also parsed
        and returned as a Python dict.

        Args:
            query_path: Path to the ``.ql`` query file to execute.
            output_path: Destination path for the SARIF result file.
                Parent directories are created automatically.
            format: Output format string understood by the CodeQL CLI.
                Defaults to ``"sarifv2.1.0"``.

        Returns:
            Parsed SARIF document as a nested Python dict.

        Raises:
            FileNotFoundError: If *query_path* does not exist.
            CodeQLError: If the CodeQL CLI exits with a non-zero code.
            json.JSONDecodeError: If the produced SARIF file is malformed JSON.
        """
        query_path = Path(query_path).resolve()
        output_path = Path(output_path)

        if not query_path.is_file():
            raise FileNotFoundError(f"Query file not found: {query_path}")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        args: list[str] = [
            "database",
            "analyze",
            str(self.db_path),
            str(query_path),
            f"--format={format}",
            f"--output={output_path}",
            "--rerun",  # always re-evaluate; do not use the cached result
        ]

        self._run(args)

        if not output_path.is_file():
            raise CodeQLError(
                f"CodeQL did not produce an output file at {output_path}",
                returncode=0,
                stderr="",
                command=args,
            )

        with output_path.open("r", encoding="utf-8") as fh:
            sarif_dict: dict[str, Any] = json.load(fh)

        logger.info("Query %s produced %s.", query_path.name, output_path)
        return sarif_dict

    def run_query_suite(
        self,
        query_paths: list[Path],
        output_dir: Path,
        max_workers: int = 4,
    ) -> list[dict[str, Any]]:
        """Run multiple ``.ql`` queries in parallel using a thread pool.

        Each query is executed by :meth:`run_query` in a separate thread.
        Failed queries are logged at ``ERROR`` level and skipped; the
        remaining results are still returned.

        Args:
            query_paths: List of ``.ql`` query file paths to execute.
            output_dir: Directory where individual SARIF output files are
                written.  Created automatically if it does not exist.
                Each query produces ``<output_dir>/<query_stem>.sarif``.
            max_workers: Maximum number of concurrent threads.  Defaults
                to ``4``.  Capped at ``len(query_paths)`` internally.

        Returns:
            A list of parsed SARIF dicts — one per *successful* query,
            in the order the queries were supplied.

        Raises:
            ValueError: If *query_paths* is empty or *max_workers* < 1.
        """
        if not query_paths:
            raise ValueError("query_paths must not be empty.")
        if max_workers < 1:
            raise ValueError(f"max_workers must be >= 1, got {max_workers!r}.")

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        effective_workers = min(max_workers, len(query_paths))

        # Preserve submission order in the result list.
        results: dict[int, dict[str, Any]] = {}

        def _run_one(index: int, qpath: Path) -> tuple[int, dict[str, Any] | None]:
            """Execute a single query and return (index, sarif_dict | None)."""
            out_file = output_dir / f"{qpath.stem}.sarif"
            try:
                sarif = self.run_query(query_path=qpath, output_path=out_file)
                return index, sarif
            except FileNotFoundError as exc:
                logger.error("Skipping query %s — file not found: %s", qpath.name, exc)
                return index, None
            except CodeQLError as exc:
                logger.error(
                    "Skipping query %s — CodeQL error (rc=%d): %s",
                    qpath.name,
                    exc.returncode,
                    exc,
                )
                return index, None
            except json.JSONDecodeError as exc:
                logger.error(
                    "Skipping query %s — malformed SARIF JSON: %s", qpath.name, exc
                )
                return index, None

        with ThreadPoolExecutor(max_workers=effective_workers) as pool:
            futures = {
                pool.submit(_run_one, idx, qp): idx
                for idx, qp in enumerate(query_paths)
            }
            for future in as_completed(futures):
                idx, sarif = future.result()
                if sarif is not None:
                    results[idx] = sarif

        # Return in original submission order.
        return [results[i] for i in sorted(results)]

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """Execute a CodeQL CLI command.

        Prepends :attr:`codeql_path` to *args*, captures both stdout and stderr,
        and enforces :attr:`timeout`.

        Args:
            args: CLI arguments to pass after the ``codeql`` executable name.
                Do **not** include ``codeql`` itself as the first element.

        Returns:
            The :class:`subprocess.CompletedProcess` object for the successful
            invocation.

        Raises:
            CodeQLError: If the process exits with a non-zero return code or if
                the executable is not found on the system.
        """
        full_cmd: list[str] = [self.codeql_path, *args]
        logger.debug("Executing: %s", " ".join(full_cmd))

        try:
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,  # we handle non-zero exits ourselves
            )
        except FileNotFoundError as exc:
            raise CodeQLError(
                f"CodeQL executable not found: {self.codeql_path!r}. "
                "Ensure it is installed and the path is correct.",
                returncode=-1,
                stderr=str(exc),
                command=full_cmd,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CodeQLError(
                f"CodeQL command timed out after {self.timeout}s.",
                returncode=-1,
                stderr=exc.stderr or "",
                command=full_cmd,
            ) from exc

        if proc.returncode != 0:
            raise CodeQLError(
                f"CodeQL exited with code {proc.returncode}.",
                returncode=proc.returncode,
                stderr=proc.stderr,
                command=full_cmd,
            )

        if proc.stdout:
            logger.debug("stdout:\n%s", proc.stdout.rstrip())
        if proc.stderr:
            # CodeQL routinely prints informational messages to stderr even on
            # success; log at DEBUG level only.
            logger.debug("stderr:\n%s", proc.stderr.rstrip())

        return proc

    # ------------------------------------------------------------------
    # Convenience / introspection helpers
    # ------------------------------------------------------------------

    def resolve_executable(self) -> Path:
        """Resolve :attr:`codeql_path` to an absolute :class:`~pathlib.Path`.

        Uses :func:`shutil.which` when the value is a bare name rather than an
        absolute path, mirroring the shell's ``$PATH`` lookup.

        Returns:
            Absolute path to the resolved ``codeql`` executable.

        Raises:
            CodeQLError: If the executable cannot be found.
        """
        resolved = shutil.which(self.codeql_path)
        if resolved is None:
            raise CodeQLError(
                f"Cannot locate '{self.codeql_path}' on $PATH.",
                returncode=-1,
                stderr="",
                command=[self.codeql_path],
            )
        return Path(resolved)

    def __repr__(self) -> str:
        return (
            f"CodeQLRunner("
            f"codeql_path={self.codeql_path!r}, "
            f"db_path={self.db_path!r}, "
            f"timeout={self.timeout!r})"
        )
