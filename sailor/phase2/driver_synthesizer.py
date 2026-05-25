"""Phase 2 — DriverSynthesizer: generate the KLEE main() driver."""

from __future__ import annotations

import logging
import re

from sailor.models.schemas import FieldClassification, GuardCondition, SymbolicInputKind, VulnerabilitySpec

logger = logging.getLogger("sailor.phase2.driver_synthesizer")


class DriverSynthesizer:
    """Generate the ``main()`` driver that sets up initial symbolic state for KLEE.

    Args:
        spec: The :class:`VulnerabilitySpec` being processed.
        field_classifications: Field-level symbolic/concrete decisions.
        guard_conditions: Guards that must be negated via klee_assume.
    """

    def __init__(
        self,
        spec: VulnerabilitySpec,
        field_classifications: list[FieldClassification],
        guard_conditions: list[GuardCondition],
    ) -> None:
        self.spec = spec
        self.field_classifications = field_classifications
        self.guard_conditions = guard_conditions

    def build_prompt(self) -> str:
        """Construct the driver synthesis prompt (Figure 3a structure).

        Returns:
            Full prompt string to send to the LLM.
        """
        spec = self.spec
        guards_str = ", ".join(g.condition for g in self.guard_conditions) or "none"

        good_sym = "klee_make_symbolic(&ctx, sizeof(ctx), \"ctx\");"
        bad_sym = "ctx->state = 7;  // hardcoded — BAD"
        good_assume = "klee_assume(ptr != NULL);"
        good_alloc = "p = calloc(1, sizeof(*p));"
        good_buf = "buf = malloc(N); klee_make_symbolic(buf, N, \"buf\");"

        field_notes = self._format_field_notes()
        guard_notes = self._format_guard_notes()

        return f"""You are an expert symbolic-execution harness author.

=== VULNERABILITY SPEC ===
l (vulnerable site): {spec.file}:{spec.line}
e (entry function):  {spec.entrypoint}
d (description):     {spec.message}
cwe:                 {spec.cwe}
snippet:             {spec.snippet}
guards:              {guards_str}
assert template:     {spec.assertion_template}

=== DRIVER RULES ===
Write a self-contained C file with int main() that:
1. Entry:    Call '{spec.entrypoint}' with properly allocated parameters.
2. Symbolic: Overapproximate inputs — make fields symbolic, not hardcoded.
   GOOD: {good_sym}
   BAD:  {bad_sym}
3. Guards:   For each guard condition, add klee_assume to negate it.
   GOOD: {good_assume}
4. Pointers: Use real allocations, NEVER NULL for concrete pointer fields.
   GOOD: {good_alloc}
5. Buffers:  Allocate then make contents symbolic.
   GOOD: {good_buf}

=== FIELD CLASSIFICATION ===
{field_notes}

=== GUARD NEGATIONS TO INCLUDE ===
{guard_notes}

=== OUTPUT FORMAT ===
Output ONLY the complete C source inside a ```c code block.
Include: <klee/klee.h>, <stdlib.h>, <string.h>
Do NOT include project headers — the slice file handles all types.
Do NOT write any prose outside the code block.
"""

    def synthesize(self, llm_response: str) -> str:
        """Extract and validate the generated driver C source.

        Args:
            llm_response: Raw LLM output containing a ```c code block.

        Returns:
            Validated driver C source string.

        Raises:
            ValueError: If the response fails structural validation.
        """
        code = _extract_c_block(llm_response)
        self._validate(code)
        return code

    def add_vulnerability_condition(
        self, driver_c: str, spec: VulnerabilitySpec
    ) -> str:
        """Add klee_assume constraints that violate the safety property.

        Inserts constraints before the call to the entry function to force
        KLEE to explore paths that trigger the vulnerability.

        Args:
            driver_c: Existing driver C source.
            spec: The vulnerability spec (used to determine CWE-specific constraints).

        Returns:
            Updated driver C source with vulnerability constraints added.
        """
        constraint = self._build_vulnerability_constraint(spec)
        if not constraint:
            return driver_c
        # Insert before the entry-function call
        entry_call_pattern = re.compile(
            rf"\b{re.escape(spec.entrypoint)}\s*\(",
            re.MULTILINE,
        )
        m = entry_call_pattern.search(driver_c)
        if m:
            insert_pos = m.start()
            return driver_c[:insert_pos] + constraint + "\n    " + driver_c[insert_pos:]
        # Fallback: append before the closing brace of main
        main_close = driver_c.rfind("}")
        if main_close != -1:
            return driver_c[:main_close] + f"    {constraint}\n" + driver_c[main_close:]
        return driver_c

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate(self, code: str) -> None:
        """Basic structural validation of generated driver.

        Raises:
            ValueError: On missing structural elements.
        """
        if "main(" not in code and "main (" not in code:
            raise ValueError("Driver missing main() function.")
        if "klee_make_symbolic" not in code:
            raise ValueError("Driver missing klee_make_symbolic calls.")
        if self.spec.entrypoint not in code:
            raise ValueError(
                f"Driver does not call entry function '{self.spec.entrypoint}'."
            )

    def _format_field_notes(self) -> str:
        if not self.field_classifications:
            return "  (no struct fields identified)"
        lines = []
        for fc in self.field_classifications:
            tag = {
                SymbolicInputKind.SYMBOLIC_SCALAR: "SYMBOLIC_SCALAR",
                SymbolicInputKind.CONCRETE_POINTER: "CONCRETE_POINTER",
                SymbolicInputKind.SYMBOLIC_BUFFER: "SYMBOLIC_BUFFER",
            }[fc.kind]
            lines.append(f"  {fc.field_type} {fc.field_name}: {tag} — {fc.reason}")
        return "\n".join(lines)

    def _format_guard_notes(self) -> str:
        if not self.guard_conditions:
            return "  (no guards identified)"
        return "\n".join(f"  {g.assume_stmt}  // at {g.location}" for g in self.guard_conditions)

    @staticmethod
    def _build_vulnerability_constraint(spec: VulnerabilitySpec) -> str:
        """Return CWE-specific klee_assume constraints that violate safety."""
        cwe = spec.cwe.upper()
        length_var = spec.length_vars[0] if spec.length_vars else "n"
        ptr_var = spec.pointer_vars[0] if spec.pointer_vars else "p"

        if cwe in ("CWE-120", "CWE-787", "CWE-122"):
            return (
                f"/* Force buffer overflow: size exceeds destination */\n"
                f"    klee_assume({length_var} > sizeof(dst_buf));\n"
                f"    klee_assume({length_var} <= sizeof(src_buf));"
            )
        if cwe == "CWE-416":
            return (
                f"/* Force use-after-free: free before dereference */\n"
                f"    free({ptr_var}); /* UAF trigger */"
            )
        if cwe == "CWE-476":
            return (
                f"/* Force null dereference */\n"
                f"    klee_assume({ptr_var} == NULL);"
            )
        if cwe == "CWE-190":
            return (
                f"/* Force integer overflow */\n"
                f"    klee_assume({length_var} > 0x7fffffff);"
            )
        return ""


def _extract_c_block(text: str) -> str:
    """Extract the first ```c ... ``` block from LLM output."""
    if "```c" in text:
        return text.split("```c")[1].split("```")[0].strip()
    if "```" in text:
        return text.split("```")[1].split("```")[0].strip()
    return text.strip()
