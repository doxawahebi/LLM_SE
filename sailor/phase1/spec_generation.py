"""Phase 1 — Specification Generation.

Converts enriched :class:`~models.schemas.FactPack` objects into
:class:`~models.schemas.VulnerabilitySpec` objects by:

1. Filtering by file and function-name skip patterns.
2. Assigning an assertion template from the CWE → template map.
3. Setting ``entrypoint = "LLM_INFER"`` (Phase 2 refines this).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

from sailor.models.schemas import FactPack, VulnerabilitySpec

logger = logging.getLogger("sailor.phase1.spec_generation")


# ---------------------------------------------------------------------------
# Filter patterns
# ---------------------------------------------------------------------------

FILE_SKIP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p) for p in [
        r".*/test[s]?/.*",
        r".*/testing/.*",
        r".*/bench(mark)?[s]?/.*",
        r".*/example[s]?/.*",
        r".*/demo[s]?/.*",
        r".*/fuzz.*/.*",
        r".*/oss-fuzz/.*",
        r".*\.gen\.(c|cpp)$",
        r".*/vendor/.*",
        r".*/third[_-]party/.*",
        r".*/external/.*",
    ]
]

FUNCTION_SKIP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p) for p in [
        r"^main$",
        r"^test_", r"_test$",
        r"^check_", r"^bench_", r"^perf_", r"^mock_",
        r"^__builtin_", r"^__asan_", r"^__ubsan_", r"^__sanitizer_",
    ]
]


# ---------------------------------------------------------------------------
# Assertion templates
# ---------------------------------------------------------------------------

ASSERTION_TEMPLATES: dict[str, str] = {
    "CWE-120": "n <= min(len(dst), len(src))",
    "CWE-121": "n <= min(len(dst), len(src))",
    "CWE-125": "n <= min(len(dst), len(src))",
    "CWE-787": "n <= min(len(dst), len(src))",
    "CWE-415": "no use of p after free(p)",
    "CWE-416": "no use of p after free(p)",
    "CWE-476": "p != NULL before *p",
    "CWE-190": "arithmetic within type range",
    "CWE-823": "offset within allocation bounds",
    "CWE-562": "no return of stack-local address",
    "CWE-674": "recursion depth bounded",
}
_DEFAULT_ASSERTION = "DERIVE_FROM_DESCRIPTION"


# ---------------------------------------------------------------------------
# Filtering helpers
# ---------------------------------------------------------------------------

def _file_is_skipped(file_path: str) -> bool:
    return any(p.search(file_path) for p in FILE_SKIP_PATTERNS)


def _function_is_skipped(func_name: str) -> bool:
    return any(p.search(func_name) for p in FUNCTION_SKIP_PATTERNS)


# ---------------------------------------------------------------------------
# SpecificationGenerator
# ---------------------------------------------------------------------------

class SpecificationGenerator:
    """Converts :class:`~models.schemas.FactPack` objects into :class:`~models.schemas.VulnerabilitySpec` objects.

    Args:
        output_dir: Directory where ``specifications.json`` and
            ``phase1_summary.json`` are written.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = Path(output_dir)

    def run(self, packs: list[FactPack]) -> list[VulnerabilitySpec]:
        """Filter and convert *packs* into vulnerability specifications.

        Args:
            packs: Enriched :class:`~models.schemas.FactPack` objects from
                :class:`~sailor.phase1.fact_enrichment.FactEnricher`.

        Returns:
            Filtered list of :class:`~models.schemas.VulnerabilitySpec` objects.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        specs: list[VulnerabilitySpec] = []

        for pack in packs:
            spec = self._convert(pack)
            if spec is not None:
                specs.append(spec)

        logger.info(
            "Specification generation: %d in → %d out (%.0f%% filtered).",
            len(packs),
            len(specs),
            100.0 * (len(packs) - len(specs)) / max(len(packs), 1),
        )
        self._write_json(specs)
        return specs

    def _convert(self, pack: FactPack) -> VulnerabilitySpec | None:
        """Apply filters and produce a :class:`~models.schemas.VulnerabilitySpec` or ``None``."""
        file_path = pack.finding.location.file
        cwe = pack.finding.cwe

        if _file_is_skipped(file_path):
            logger.debug("SKIP (file pattern): %s", file_path)
            return None

        # Determine the vulnerable function name for entrypoint / filtering.
        # Phase 2 LLM may refine this; for now use the suspect call heuristic
        # or fall back to "LLM_INFER" per spec §3.2.
        entrypoint = self._resolve_entrypoint(pack)

        if _function_is_skipped(entrypoint) and entrypoint != "LLM_INFER":
            logger.debug("SKIP (function pattern): %s", entrypoint)
            return None

        assertion = ASSERTION_TEMPLATES.get(cwe, _DEFAULT_ASSERTION)

        try:
            return VulnerabilitySpec.from_fact_pack(
                pack=pack,
                entrypoint=entrypoint,
                assertion_template=assertion,
            )
        except Exception as exc:
            logger.warning("Failed to build VulnerabilitySpec for %s: %s",
                           pack.finding.finding_id, exc)
            return None

    @staticmethod
    def _resolve_entrypoint(pack: FactPack) -> str:
        """Determine the entry-point function name for symbolic execution.

        Strategy (Phase 1):
          1. Regex on SARIF description for "... in funcName()".
          2. Tree-sitter: find the C function enclosing the finding line.
          3. Fallback: ``"LLM_INFER"`` so Phase 2 resolves via source exploration.

        Phase 2 LLM always has the opportunity to override this value.
        """
        # 1. Description regex
        desc = pack.finding.description
        m = re.search(r"\bin\s+(\w+)\s*\(", desc)
        if m:
            candidate = m.group(1)
            if not _function_is_skipped(candidate):
                return candidate

        # 2. Tree-sitter enclosing-function extraction
        src_path = Path(pack.finding.location.file)
        vuln_line = pack.finding.location.line
        if src_path.is_file():
            try:
                source = src_path.read_text(encoding="utf-8", errors="replace")
                func_name = _extract_enclosing_function_name(source, vuln_line)
                if func_name and not _function_is_skipped(func_name):
                    return func_name
            except Exception:
                pass

        return "LLM_INFER"

    def _write_json(self, specs: list[VulnerabilitySpec]) -> None:
        out = self.output_dir / "specifications.json"
        payload = [s.model_dump() for s in specs]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote %s (%d specifications).", out, len(specs))

    @classmethod
    def load(cls, output_dir: Path) -> list[VulnerabilitySpec]:
        """Load previously written specifications from ``<output_dir>/specifications.json``.

        Args:
            output_dir: Directory containing ``specifications.json``.

        Returns:
            List of :class:`~models.schemas.VulnerabilitySpec` objects.

        Raises:
            FileNotFoundError: If ``specifications.json`` does not exist.
        """
        path = Path(output_dir) / "specifications.json"
        if not path.is_file():
            raise FileNotFoundError(f"specifications.json not found at {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        return [VulnerabilitySpec.model_validate(item) for item in raw]


def _extract_enclosing_function_name(source: str, vuln_line: int) -> str | None:
    """Return the name of the C function enclosing *vuln_line* using tree-sitter.

    Args:
        source: Full source text of the C file.
        vuln_line: 1-based line number of the vulnerability.

    Returns:
        Function name string, or ``None`` if not determinable.
    """
    try:
        parser = Parser(Language(tsc.language()))
        tree = parser.parse(source.encode("utf-8", errors="replace"))
    except Exception:
        return None

    def _find_func(node) -> object | None:
        if node.type == "function_definition":
            if node.start_point[0] <= vuln_line - 1 <= node.end_point[0]:
                # function_definition → declarator → ... → identifier
                for child in node.children:
                    if child.type in ("function_declarator", "pointer_declarator"):
                        for gc in child.children:
                            if gc.type == "function_declarator":
                                for ggc in gc.children:
                                    if ggc.type == "identifier":
                                        return source[ggc.start_byte:ggc.end_byte]
                            if gc.type == "identifier":
                                return source[gc.start_byte:gc.end_byte]
                    if child.type == "identifier":
                        return source[child.start_byte:child.end_byte]
        for child in node.children:
            result = _find_func(child)
            if result is not None:
                return result
        return None

    result = _find_func(tree.root_node)
    return str(result) if result else None
