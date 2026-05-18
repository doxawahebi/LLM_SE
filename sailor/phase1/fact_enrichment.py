"""Phase 1 — Fact Enrichment.

Applies five regex-based extractors to each :class:`~models.schemas.SARIFFinding`
and packages the result into a :class:`~models.schemas.FactPack`.

Extractors
----------
1. **Suspect Calls**   — dangerous API names in the full function body.
2. **Pointer Vars**    — pointer-typed variable names in the function body.
3. **Length Vars**     — variables with size/length semantics in the function body.
4. **Bounds Hints**    — comparison expressions in ℓ ± 20 lines.
5. **Build Context**   — ``-I`` and ``-D`` flags from ``compile_commands.json``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

from models.schemas import BuildContext, FactPack, SARIFFinding

logger = logging.getLogger("sailor.phase1.fact_enrichment")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_FUNCTIONS: frozenset[str] = frozenset({
    "memcpy", "memmove", "memset", "strncpy", "strncat",
    "sprintf", "snprintf", "malloc", "calloc", "realloc",
    "free", "bfd_zalloc", "bfd_alloc", "alloca",
    "xmalloc", "xrealloc", "g_malloc", "g_realloc",
})

_RE_CALL        = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
_RE_POINTER_VAR = re.compile(r"[\w\s]+\*+\s+(\w+)")
_RE_LENGTH_VAR  = re.compile(r"\b(\w*(?:len|size|count|capacity)\w*)\b", re.IGNORECASE)
_RE_BOUNDS_HINT = re.compile(r"\b\w+\s*(>=|<=|>|<|==|!=)\s*[\w\(\)]+")


# ---------------------------------------------------------------------------
# Tree-sitter helpers
# ---------------------------------------------------------------------------

def _build_parser() -> Parser:
    return Parser(Language(tsc.language()))


def _extract_function_body(source: str, vuln_line: int, parser: Parser) -> str | None:
    """Return the source text of the C function that contains *vuln_line* (1-indexed).

    Returns ``None`` when no enclosing function definition is found.
    """
    tree = parser.parse(source.encode("utf-8", errors="replace"))

    def _find(node) -> object | None:
        if node.type == "function_definition":
            if node.start_point[0] <= vuln_line - 1 <= node.end_point[0]:
                return node
        for child in node.children:
            result = _find(child)
            if result is not None:
                return result
        return None

    target = _find(tree.root_node)
    if target is None:
        return None
    return source[target.start_byte: target.end_byte]


# ---------------------------------------------------------------------------
# Per-extractor functions
# ---------------------------------------------------------------------------

def _extract_suspect_calls(body: str) -> list[str]:
    """Return names of dangerous API calls that appear in *body*."""
    names = _RE_CALL.findall(body)
    return sorted({n for n in names if n in DANGEROUS_FUNCTIONS})


def _extract_pointer_vars(body: str) -> list[str]:
    """Return pointer-typed variable names declared in *body*."""
    matches = _RE_POINTER_VAR.findall(body)
    return sorted(set(matches))


def _extract_length_vars(body: str) -> list[str]:
    """Return variables with size/length semantics in *body*."""
    matches = _RE_LENGTH_VAR.findall(body)
    # Filter out C keywords and common false positives
    _KEYWORD_RE = re.compile(r"^(sizeof|size_t|size_of|capacity_of)$", re.IGNORECASE)
    return sorted({m for m in matches if not _KEYWORD_RE.match(m)})


def _extract_bounds_hints(source_lines: list[str], vuln_line: int) -> list[str]:
    """Return comparison expressions in the ℓ ± 20 line window around *vuln_line*."""
    lo = max(0, vuln_line - 1 - 20)
    hi = min(len(source_lines), vuln_line + 20)
    window = "\n".join(source_lines[lo:hi])
    return [m.group(0).strip() for m in _RE_BOUNDS_HINT.finditer(window)]


def _extract_build_context(project_root: Path, source_file: str) -> BuildContext:
    """Parse ``compile_commands.json`` for ``-I`` and ``-D`` flags for *source_file*.

    Falls back to an empty :class:`~models.schemas.BuildContext` when the file
    is absent or the entry for *source_file* cannot be located.
    """
    cc_path = project_root / "compile_commands.json"
    if not cc_path.is_file():
        return BuildContext()

    try:
        entries = json.loads(cc_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read compile_commands.json: %s", exc)
        return BuildContext()

    # Match by file name suffix (relative paths in compile_commands may vary)
    source_stem = Path(source_file).name
    command_str = ""
    for entry in entries:
        f = entry.get("file", "")
        if f.endswith(source_stem) or Path(f).resolve() == Path(source_file).resolve():
            command_str = entry.get("command", "") or " ".join(entry.get("arguments", []))
            break

    if not command_str:
        return BuildContext()

    include_paths = re.findall(r"-I\s*(\S+)", command_str)
    defines       = re.findall(r"-D\s*(\S+)", command_str)
    return BuildContext(include_paths=include_paths, defines=defines)


# ---------------------------------------------------------------------------
# FactEnricher
# ---------------------------------------------------------------------------

class FactEnricher:
    """Applies all five enrichment extractors to a list of :class:`~models.schemas.SARIFFinding` objects.

    Args:
        project_root: Absolute path to the analysed project's source root.
        output_dir: Directory where ``fact_packs.json`` is written.
    """

    def __init__(self, project_root: Path, output_dir: Path) -> None:
        self.project_root = Path(project_root).resolve()
        self.output_dir = Path(output_dir)
        self._parser = _build_parser()

    def run(self, findings: list[SARIFFinding]) -> list[FactPack]:
        """Enrich *findings* and return a :class:`~models.schemas.FactPack` per finding.

        Findings whose source file cannot be read are silently skipped.

        Args:
            findings: Raw :class:`~models.schemas.SARIFFinding` objects from
                :class:`~sailor.phase1.fact_generation.FactGenerator`.

        Returns:
            List of :class:`~models.schemas.FactPack` objects, one per
            successfully enriched finding.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        packs: list[FactPack] = []

        for finding in findings:
            pack = self._enrich_one(finding)
            if pack is not None:
                packs.append(pack)

        logger.info("Enriched %d / %d findings into FactPacks.", len(packs), len(findings))
        self._write_json(packs)
        return packs

    def _enrich_one(self, finding: SARIFFinding) -> FactPack | None:
        src_path = Path(finding.location.file)
        if not src_path.is_file():
            logger.warning("Source file not found, skipping: %s", src_path)
            return None

        try:
            source = src_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", src_path, exc)
            return None

        source_lines = source.splitlines()
        vuln_line = finding.location.line

        # Extract function body for per-body extractors
        body = _extract_function_body(source, vuln_line, self._parser)
        if body is None:
            logger.debug(
                "No enclosing function at line %d in %s — using ±50 line window.",
                vuln_line, src_path,
            )
            lo = max(0, vuln_line - 1 - 50)
            hi = min(len(source_lines), vuln_line + 50)
            body = "\n".join(source_lines[lo:hi])

        suspect_calls = _extract_suspect_calls(body)
        pointer_vars  = _extract_pointer_vars(body)
        length_vars   = _extract_length_vars(body)
        bounds_hints  = _extract_bounds_hints(source_lines, vuln_line)
        build_ctx     = _extract_build_context(self.project_root, finding.location.file)

        return FactPack(
            finding=finding,
            suspect_calls=suspect_calls,
            pointer_vars=pointer_vars,
            length_vars=length_vars,
            bounds_hints=bounds_hints,
            build_context=build_ctx,
        )

    def _write_json(self, packs: list[FactPack]) -> None:
        out = self.output_dir / "fact_packs.json"
        payload = [p.model_dump() for p in packs]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote %s (%d fact packs).", out, len(packs))

    # ------------------------------------------------------------------
    # Alternative: load from existing fact_packs.json
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, output_dir: Path) -> list[FactPack]:
        """Load previously written fact packs from ``<output_dir>/fact_packs.json``.

        Args:
            output_dir: Directory containing ``fact_packs.json``.

        Returns:
            List of :class:`~models.schemas.FactPack` objects.

        Raises:
            FileNotFoundError: If ``fact_packs.json`` does not exist.
        """
        path = Path(output_dir) / "fact_packs.json"
        if not path.is_file():
            raise FileNotFoundError(f"fact_packs.json not found at {path}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        return [FactPack.model_validate(item) for item in raw]
