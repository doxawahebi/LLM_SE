"""Phase 2 — SourceExplorer: LLM tool calls for reading project source."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from sailor.models.schemas import FieldClassification, GuardCondition, SymbolicInputKind, VulnerabilitySpec

logger = logging.getLogger("sailor.phase2.source_explorer")


class SourceExplorer:
    """Execute LLM source-reading tool calls against the project root.

    All grep operations are read-only and scoped to the project directory.

    Args:
        project_root: Absolute path to the C/C++ project source tree.
    """

    def __init__(self, project_root: Path) -> None:
        self.project_root = Path(project_root)

    # ------------------------------------------------------------------
    # Public tool-call methods
    # ------------------------------------------------------------------

    def get_function_signature(self, function_name: str) -> str:
        """Search project headers and sources for a function signature.

        Args:
            function_name: C function name to look up.

        Returns:
            Matching lines with ±5 lines of context, or a not-found message.
        """
        patterns = [
            f"^[^/]*{re.escape(function_name)}\\s*(",
            f"\\b{re.escape(function_name)}\\s*(",
        ]
        for pattern in patterns:
            result = self._grep(pattern, include=["*.h", "*.c"], context=5)
            if result.strip():
                return result
        return f"[SourceExplorer] Function '{function_name}' not found in project headers."

    def get_struct_definition(self, struct_name: str) -> str:
        """Return the full struct body for a given struct name.

        Handles ``typedef struct`` patterns.

        Args:
            struct_name: C struct or typedef name.

        Returns:
            Struct definition text, or a not-found message.
        """
        pattern = f"(typedef\\s+)?struct\\s+{re.escape(struct_name)}\\b"
        result = self._grep(pattern, include=["*.h", "*.c"], context=20)
        if result.strip():
            return result
        # Also search by typedef alias
        result = self._grep(f"\\b{re.escape(struct_name)}\\b", include=["*.h"], context=10)
        if result.strip():
            return result
        return f"[SourceExplorer] Struct '{struct_name}' not found."

    def get_type_declaration(self, type_name: str) -> str:
        """Search for a typedef, enum, or macro definition.

        Args:
            type_name: C type or macro name.

        Returns:
            Declaration lines with file:line prefix.
        """
        result = self._grep(
            f"(typedef|enum|#define)\\s.*\\b{re.escape(type_name)}\\b",
            include=["*.h", "*.c"],
            context=3,
        )
        if result.strip():
            return result
        return f"[SourceExplorer] Type '{type_name}' not found."

    def get_call_chain(self, entry: str, target: str) -> list[str]:
        """Approximate the call chain from entry to target using grep.

        Uses a heuristic: grep for function bodies containing calls to the
        next function in the chain until target is reached.

        Args:
            entry: Entry-point function name.
            target: Target vulnerable function name.

        Returns:
            Ordered list of function names from entry to target.
        """
        chain = [entry]
        if entry == target:
            return chain
        # BFS approximation: look for callers of target then trace back
        visited: set[str] = {entry}
        callers = self._find_callers(target)
        # Build a simple path: entry -> intermediate -> target
        for caller in callers:
            if caller == entry:
                chain = [entry, target]
                return chain
            if caller not in visited:
                chain = [entry, caller, target]
                return chain
        # Fallback: just return entry and target
        chain = [entry, target]
        return chain

    def get_file_slice(self, file: str, start_line: int, end_line: int) -> str:
        """Return lines [start_line, end_line] from a file.

        Args:
            file: Relative or absolute file path.
            start_line: First line to return (1-based).
            end_line: Last line to return (1-based, inclusive).

        Returns:
            File content slice as a string.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file)
        if not path.is_absolute():
            path = self.project_root / file
        if not path.exists():
            return f"[SourceExplorer] File not found: {file}"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, start_line - 1)
        end = min(len(lines), end_line)
        numbered = [f"{start + i + 1}: {line}" for i, line in enumerate(lines[start:end])]
        return "\n".join(numbered)

    def identify_guards(self, call_chain: list[str]) -> list[GuardCondition]:
        """Scan call-chain functions for early-exit null/false checks.

        Args:
            call_chain: Ordered list of function names forming the call path.

        Returns:
            List of :class:`GuardCondition` instances with klee_assume stmts.
        """
        guards: list[GuardCondition] = []
        null_check = re.compile(
            r"if\s*\(\s*(!?\s*\w+\s*(==\s*NULL|!=\s*NULL)?)\s*\)\s*return"
        )
        for func in call_chain:
            result = self._grep(
                f"^[^{{}}]*{re.escape(func)}\\s*\\(",
                include=["*.c"],
                context=0,
            )
            if not result.strip():
                continue
            # Find the file that defines this function
            for line in result.splitlines():
                if ":" not in line:
                    continue
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                file_path = parts[0]
                # Read function body and scan for guards
                path = Path(file_path)
                if not path.is_absolute():
                    path = self.project_root / file_path
                if not path.exists():
                    continue
                src = path.read_text(encoding="utf-8", errors="replace")
                for m in null_check.finditer(src):
                    expr = m.group(1).strip()
                    lineno = src[: m.start()].count("\n") + 1
                    location = f"{file_path}:{lineno}"
                    # Build negation for klee_assume
                    assume = self._negate_guard(expr)
                    guards.append(
                        GuardCondition(
                            condition=expr,
                            assume_stmt=f"klee_assume({assume});",
                            location=location,
                        )
                    )
        # Deduplicate by condition
        seen: set[str] = set()
        unique: list[GuardCondition] = []
        for g in guards:
            if g.condition not in seen:
                seen.add(g.condition)
                unique.append(g)
        return unique

    def classify_fields(
        self,
        spec: VulnerabilitySpec,
        struct_name: str,
    ) -> list[FieldClassification]:
        """Classify struct fields as symbolic scalar, concrete pointer, or symbolic buffer.

        Args:
            spec: The VulnerabilitySpec containing assertion_template and length_vars.
            struct_name: The struct whose fields should be classified.

        Returns:
            List of :class:`FieldClassification` instances.
        """
        struct_text = self.get_struct_definition(struct_name)
        fields = self._parse_struct_fields(struct_text)
        assertion_vars = set(spec.length_vars + spec.pointer_vars)
        classifications: list[FieldClassification] = []
        for field_type, field_name in fields:
            if field_name in assertion_vars or any(
                v in field_name for v in spec.length_vars
            ):
                kind = SymbolicInputKind.SYMBOLIC_SCALAR
                reason = "appears in assertion_template or length_vars"
            elif "*" in field_type or field_type.endswith("_t *") or "ptr" in field_name.lower():
                kind = SymbolicInputKind.CONCRETE_POINTER
                reason = "pointer field — must be allocated with calloc"
            elif "buf" in field_name.lower() or "data" in field_name.lower() or "[" in field_type:
                kind = SymbolicInputKind.SYMBOLIC_BUFFER
                reason = "buffer field — allocate and make contents symbolic"
            else:
                kind = SymbolicInputKind.SYMBOLIC_SCALAR
                reason = "scalar field — default to symbolic"
            classifications.append(
                FieldClassification(
                    field_name=field_name,
                    field_type=field_type.strip(),
                    kind=kind,
                    reason=reason,
                )
            )
        return classifications

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _grep(
        self,
        pattern: str,
        include: list[str] | None = None,
        context: int = 0,
    ) -> str:
        """Run grep -rn against the project root.

        Args:
            pattern: Extended regex pattern.
            include: File glob patterns (e.g. ``["*.h", "*.c"]``).
            context: Lines of surrounding context.

        Returns:
            grep output string (empty string on no match or error).
        """
        cmd = ["grep", "-rn", "-E", pattern]
        for inc in (include or []):
            cmd += ["--include", inc]
        if context > 0:
            cmd += ["-C", str(context)]
        cmd.append(str(self.project_root))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("grep failed: %s", exc)
            return ""

    def _find_callers(self, function_name: str) -> list[str]:
        """Find function names that call *function_name*.

        Returns up to 5 candidate caller names.
        """
        result = self._grep(
            f"\\b{re.escape(function_name)}\\s*\\(",
            include=["*.c"],
            context=5,
        )
        func_def = re.compile(r"^\w[\w\s\*]+\b(\w+)\s*\([^)]*\)\s*\{", re.MULTILINE)
        callers: list[str] = []
        for m in func_def.finditer(result):
            name = m.group(1)
            if name != function_name and name not in callers:
                callers.append(name)
            if len(callers) >= 5:
                break
        return callers

    @staticmethod
    def _negate_guard(expr: str) -> str:
        """Return the logical negation of a guard expression.

        E.g. ``"ptr == NULL"`` → ``"ptr != NULL"``,
             ``"!p"``          → ``"p"``.
        """
        expr = expr.strip()
        if "== NULL" in expr:
            return expr.replace("== NULL", "!= NULL")
        if "!= NULL" in expr:
            return expr.replace("!= NULL", "== NULL")
        if expr.startswith("!"):
            return expr[1:]
        return f"!({expr})"

    @staticmethod
    def _parse_struct_fields(struct_text: str) -> list[tuple[str, str]]:
        """Extract (type, name) pairs from a struct definition snippet.

        Args:
            struct_text: Raw grep output containing a struct body.

        Returns:
            List of ``(type_str, field_name)`` tuples.
        """
        # Pattern handles both "int x;" and "char *name;" (pointer adjacent to name)
        field_re = re.compile(
            r"^\s*([\w\s\*]+?)\s+\*?\s*(\w+)\s*;",
            re.MULTILINE,
        )
        results: list[tuple[str, str]] = []
        for m in field_re.finditer(struct_text):
            ftype = m.group(1).strip()
            fname = m.group(2).strip()
            if ftype not in ("typedef", "struct", "enum", "union", "return", "if", "while"):
                results.append((ftype, fname))
        return results
