"""Phase 1 — Fact Generation.

Runs all CodeQL queries against a pre-built database and parses the resulting
SARIF files into :class:`~models.schemas.SARIFFinding` objects.

Internal pipeline::

    CodeQL DB → run_query_suite (parallel) → SARIF files
             → parse each result → SARIFFinding list (findings.json)
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Any

from codeql.wrapper import CodeQLError, CodeQLRunner
from models.schemas import BuildContext, Location, SARIFFinding, TraceStep
from sailor.codeql.queries import CodeQLQuerySuite

logger = logging.getLogger("sailor.phase1.fact_generation")

# Regex to strip URI base placeholders such as %SRCROOT%
_URI_BASE_RE = re.compile(r"^%[A-Z_]+%/?")


# ---------------------------------------------------------------------------
# SARIF parsing helpers
# ---------------------------------------------------------------------------

def _resolve_uri(uri: str, project_root: Path) -> Path:
    """Convert a SARIF artifact URI to an absolute filesystem path.

    Strips leading ``%SRCROOT%`` (or similar) placeholders before joining
    with *project_root*.
    """
    clean = _URI_BASE_RE.sub("", uri)
    candidate = Path(clean)
    if candidate.is_absolute():
        return candidate
    return (project_root / candidate).resolve()


def _read_snippet(file_path: Path, line: int) -> str:
    """Read the source line at *line* (1-indexed) from *file_path*.

    Returns an empty string when the file cannot be read or the line number
    is out of range.  The caller is responsible for further truncation.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:120]
    except OSError:
        pass
    return ""


def _parse_trace(result: dict[str, Any]) -> list[TraceStep]:
    """Extract taint-flow trace steps from SARIF ``codeFlows``.

    Returns an empty list for queries without code-flow information (i.e.
    ``@kind problem`` queries as opposed to ``@kind path-problem``).
    """
    steps: list[TraceStep] = []
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            locations = thread.get("locations", [])
            for i, tfl in enumerate(locations):
                loc_obj = tfl.get("location", {})
                phys = loc_obj.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                msg = loc_obj.get("message", {}).get("text", "")

                uri = art.get("uri", "")
                line = region.get("startLine", 1)
                col = region.get("startColumn", 1)

                if i == 0:
                    label = "source"
                elif i == len(locations) - 1:
                    label = "sink"
                else:
                    label = "step"

                # Override with explicit label from message if present
                if "source" in msg.lower():
                    label = "source"
                elif "sink" in msg.lower():
                    label = "sink"

                steps.append(TraceStep(file=uri, line=max(line, 1), col=max(col, 1), label=label))
    return steps


def _parse_result(
    result: dict[str, Any],
    project_root: Path,
) -> SARIFFinding | None:
    """Convert one SARIF result entry to a :class:`SARIFFinding`.

    Returns ``None`` when the entry is malformed or the source file cannot
    be found on disk.
    """
    rule_id: str = result.get("ruleId", "")
    if not rule_id:
        logger.debug("Skipping SARIF result with no ruleId.")
        return None

    locations = result.get("locations", [])
    if not locations:
        logger.debug("Skipping result %s — no locations.", rule_id)
        return None

    phys = locations[0].get("physicalLocation", {})
    art = phys.get("artifactLocation", {})
    region = phys.get("region", {})

    uri = art.get("uri", "")
    if not uri:
        logger.debug("Skipping result %s — no URI.", rule_id)
        return None

    start_line = region.get("startLine", 1)
    start_col = region.get("startColumn", 1)
    end_col = region.get("endColumn", start_col)
    if end_col < start_col:
        end_col = start_col

    file_path = _resolve_uri(uri, project_root)
    description = result.get("message", {}).get("text", "")
    if not description:
        description = f"{rule_id} finding at {uri}:{start_line}"

    snippet = _read_snippet(file_path, start_line)

    loc = Location(
        file=str(file_path),
        line=max(start_line, 1),
        col_start=max(start_col, 1),
        col_end=max(end_col, 1),
    )
    trace = _parse_trace(result)

    try:
        finding = SARIFFinding(
            rule_id=rule_id,
            location=loc,
            description=description,
            trace=trace,
            snippet=snippet,
        )
        return finding
    except Exception as exc:  # pydantic ValidationError
        logger.warning("Skipping malformed finding %s: %s", rule_id, exc)
        return None


def _parse_sarif(sarif_dict: dict[str, Any], project_root: Path) -> list[SARIFFinding]:
    """Parse all results from a single SARIF document."""
    findings: list[SARIFFinding] = []
    for run in sarif_dict.get("runs", []):
        for result in run.get("results", []):
            finding = _parse_result(result, project_root)
            if finding is not None:
                findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# FactGenerator
# ---------------------------------------------------------------------------

class FactGenerator:
    """Runs all CodeQL queries and converts SARIF output to :class:`SARIFFinding` objects.

    Args:
        runner: Configured :class:`~codeql.wrapper.CodeQLRunner` pointing at an
            existing CodeQL database.
        suite: The :class:`~sailor.codeql.queries.CodeQLQuerySuite` providing
            all 34 query definitions.
        project_root: Absolute path to the analysed project's source root.
        output_dir: Directory where ``findings.json`` and per-query SARIF files
            are written.
        codeql_home: Optional path to the CodeQL installation root.  Required
            only when standard queries should be executed.
        max_workers: Maximum number of parallel CodeQL invocations.
    """

    def __init__(
        self,
        runner: CodeQLRunner,
        suite: CodeQLQuerySuite,
        project_root: Path,
        output_dir: Path,
        *,
        codeql_home: Path | None = None,
        max_workers: int = 4,
    ) -> None:
        self.runner = runner
        self.suite = suite
        self.project_root = Path(project_root).resolve()
        self.output_dir = Path(output_dir)
        self.codeql_home = Path(codeql_home) if codeql_home else None
        self.max_workers = max_workers

    def run(self) -> list[SARIFFinding]:
        """Execute all queries and return the parsed findings list.

        The findings are also serialised to ``<output_dir>/findings.json``.

        Returns:
            List of :class:`~models.schemas.SARIFFinding` objects, one per
            parseable SARIF result across all queries.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        sarif_dir = self.output_dir / "sarif_per_query"
        ql_dir = self.output_dir / "custom_ql"

        query_paths = self.suite.all_query_paths(
            custom_dir=ql_dir,
            codeql_home=self.codeql_home,
        )
        logger.info("Running %d queries (max_workers=%d).", len(query_paths), self.max_workers)

        sarif_results: list[dict[str, Any]] = self.runner.run_query_suite(
            query_paths=query_paths,
            output_dir=sarif_dir,
            max_workers=self.max_workers,
        )
        logger.info("Received %d SARIF documents.", len(sarif_results))

        findings: list[SARIFFinding] = []
        seen_ids: set[str] = set()
        for sarif_doc in sarif_results:
            for f in _parse_sarif(sarif_doc, self.project_root):
                if f.finding_id not in seen_ids:
                    seen_ids.add(f.finding_id)
                    findings.append(f)

        logger.info("Parsed %d unique findings.", len(findings))
        self._write_json(findings)
        return findings

    def _write_json(self, findings: list[SARIFFinding]) -> None:
        out = self.output_dir / "findings.json"
        payload = [f.model_dump() for f in findings]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote %s (%d findings).", out, len(findings))

    # ------------------------------------------------------------------
    # Alternative: load from existing findings.json
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, output_dir: Path) -> list[SARIFFinding]:
        """Load :class:`SARIFFinding` objects from a previously written ``findings.json``.

        This allows Phase 1 to resume from an existing fact-generation result
        without re-running CodeQL.

        Args:
            output_dir: Directory containing ``findings.json``.

        Returns:
            List of :class:`~models.schemas.SARIFFinding` objects.

        Raises:
            FileNotFoundError: If ``findings.json`` does not exist.
        """
        path = Path(output_dir) / "findings.json"
        if not path.is_file():
            raise FileNotFoundError(f"findings.json not found at {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        return [SARIFFinding.model_validate(item) for item in raw]
