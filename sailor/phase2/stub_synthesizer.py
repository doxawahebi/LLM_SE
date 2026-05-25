"""Phase 2 — StubSynthesizer: generate the code slice + stubs C file."""

from __future__ import annotations

import logging
import re

from sailor.models.schemas import VulnerabilitySpec
from sailor.phase2.source_explorer import SourceExplorer

logger = logging.getLogger("sailor.phase2.stub_synthesizer")


class StubSynthesizer:
    """Generate the self-contained code-slice C file.

    The slice contains only the call chain from the entry function ``e`` to
    the vulnerable site ``ℓ``, with all external dependencies stubbed out.

    Args:
        spec: The :class:`VulnerabilitySpec` being processed.
        source_explorer: A :class:`SourceExplorer` instance for reading source.
        call_chain: Ordered list of function names from entry to vulnerable site.
    """

    def __init__(
        self,
        spec: VulnerabilitySpec,
        source_explorer: SourceExplorer,
        call_chain: list[str],
    ) -> None:
        self.spec = spec
        self.source_explorer = source_explorer
        self.call_chain = call_chain

    def build_prompt(self) -> str:
        """Build the stub synthesis prompt (Figure 4a structure).

        Returns:
            Full prompt string to send to the LLM.
        """
        spec = self.spec
        chain_str = " → ".join(self.call_chain)

        on_path = chain_str
        off_path_example = "any branch/loop NOT on the path to the vulnerable site"

        good_entry = f"int {spec.entrypoint}(Type *ctx) {{ vul_func(ctx); return 0; }}"
        bad_stub = "int f(...) { return -300; }  // BAD: hardcoded"
        good_stub = (
            "int f(...) {\n"
            "    int r;\n"
            "    klee_make_symbolic(&r, sizeof(r), \"r\");\n"
            "    return r;\n"
            "}  // GOOD: symbolic return"
        )
        probe = 'klee_warning_once("SPINE_PROBE:<func>:ENTRY");'

        return f"""You are an expert at writing self-contained KLEE code slices.

=== VULNERABILITY SPEC ===
target (vulnerable site ℓ): {spec.file}:{spec.line}
entry function (e):         {spec.entrypoint}
cwe:                        {spec.cwe}
snippet at ℓ:               {spec.snippet}
call chain (e → ℓ):         {chain_str}

=== CODE SLICE RULES ===
Write a single self-contained C file that contains ONLY:
  1. Minimal type definitions (only fields accessed by the sliced code).
  2. The functions in the call chain ({chain_str}).
  3. Symbolic stubs for all external callees NOT in the call chain.

FOUR stub granularities — ALL are required:

A. FUNCTION-LEVEL (off-path callees):
   BAD:  {bad_stub}
   GOOD: {good_stub}
   EXCEPTION: CWE-416 — free() stub MUST call real free():
     void free(void *p) {{ extern void __real_free(void*); __real_free(p); }}

B. BRANCH-LEVEL (off-path if/switch):
   Replace off-path if(cond) {{ ... }} with if(0) {{ }}
   Replace off-path switch cases with break.

C. LOOP-LEVEL (loops enclosing ℓ):
   Convert while/for/do-while that ENCLOSE ℓ to if(1) {{ body }}
   This bounds KLEE to a single pass.

D. TYPE-LEVEL (struct fields):
   Redefine structs with ONLY the fields accessed in the sliced code.
   This avoids transitive header dependencies.

=== REACHABILITY PROBES ===
At the ENTRY of EVERY function in the slice, add:
  {probe}
(replace <func> with the actual function name)

=== ON-PATH vs OFF-PATH ===
ON-PATH statements: {on_path}
OFF-PATH: {off_path_example}

=== IMPORTANT ===
- Do NOT #include any project headers.
- Do NOT use any external symbols not defined in this file
  (except malloc, calloc, free, klee_make_symbolic, klee_warning_once,
   klee_assume, klee_assert — these are provided by KLEE runtime).
- Insert klee_assert(0 && "SAILOR_SINK_REACHED") immediately AFTER
  the vulnerable statement at line {spec.line} in '{spec.file}'.

=== OUTPUT FORMAT ===
Output ONLY the complete C source inside a ```c code block. No prose.
"""

    def synthesize(self, llm_response: str) -> str:
        """Extract and validate the generated code-slice C source.

        Args:
            llm_response: Raw LLM output.

        Returns:
            Validated code-slice C source.

        Raises:
            ValueError: If structural validation fails.
        """
        code = _extract_c_block(llm_response)
        self._validate(code)
        return code

    def inject_reachability_assertion(self, slice_c: str) -> str:
        """Insert klee_assert(0 && "SAILOR_SINK_REACHED") after the vulnerable statement.

        If the assertion is already present, returns slice_c unchanged.

        Args:
            slice_c: Code slice C source.

        Returns:
            Updated source with the reachability assertion injected.
        """
        if "SAILOR_SINK_REACHED" in slice_c:
            return slice_c
        # Look for the snippet (or a close approximation) to find the insertion point
        snippet = self.spec.snippet.strip()
        if snippet and snippet in slice_c:
            idx = slice_c.index(snippet) + len(snippet)
            semicolon_pos = slice_c.find(";", idx)
            if semicolon_pos != -1:
                insert_after = semicolon_pos + 1
                assertion = '\n    klee_assert(0 && "SAILOR_SINK_REACHED");'
                return slice_c[:insert_after] + assertion + slice_c[insert_after:]
        # Fallback: append at end of last function body
        last_brace = slice_c.rfind("}")
        if last_brace != -1:
            assertion = '\n    klee_assert(0 && "SAILOR_SINK_REACHED");\n'
            return slice_c[:last_brace] + assertion + slice_c[last_brace:]
        return slice_c

    def _apply_function_level_stubs(
        self, functions: list[str], call_chain: list[str]
    ) -> list[str]:
        """Replace off-path callee bodies with symbolic-return stubs.

        CWE-416 exception: free() must call __real_free().

        Args:
            functions: All function names appearing in the slice.
            call_chain: Functions that must retain their real bodies.

        Returns:
            Updated function source list.
        """
        cwe = self.spec.cwe.upper()
        stubbed: list[str] = []
        for func in functions:
            if func in call_chain:
                stubbed.append(func)
            elif cwe == "CWE-416" and func == "free":
                stubbed.append(
                    "void free(void *p) { extern void __real_free(void*); __real_free(p); }"
                )
            else:
                stubbed.append(
                    f"/* STUB: {func} */\n"
                    f"static int {func}_stub_retval;\n"
                    f"static int {func}(void) {{\n"
                    f"    klee_make_symbolic(&{func}_stub_retval, "
                    f"sizeof({func}_stub_retval), \"{func}_ret\");\n"
                    f"    return {func}_stub_retval;\n"
                    f"}}"
                )
        return stubbed

    def _apply_branch_level_stubs(self, source: str) -> str:
        """Replace off-path if blocks with if(0) {}.

        Uses a conservative heuristic: any if-block that does not contain
        the snippet text is treated as off-path.

        Args:
            source: C source code string.

        Returns:
            Modified source.
        """
        snippet = self.spec.snippet.strip()
        if not snippet:
            return source
        # Replace if-blocks that don't contain the snippet
        def replace_offpath_if(m: re.Match) -> str:
            block = m.group(0)
            if snippet in block:
                return block
            return "if(0) { /* off-path stub */ }"

        pattern = re.compile(r"if\s*\([^)]+\)\s*\{[^{}]*\}", re.DOTALL)
        return pattern.sub(replace_offpath_if, source)

    def _apply_loop_level_stubs(self, source: str) -> str:
        """Convert loops enclosing ℓ to if(1) { body }.

        Args:
            source: C source code string.

        Returns:
            Modified source.
        """
        snippet = self.spec.snippet.strip()
        if not snippet:
            return source

        def replace_loop(m: re.Match) -> str:
            block = m.group(0)
            if snippet in block:
                # Extract body and wrap in if(1)
                brace_start = block.index("{")
                body = block[brace_start:]
                return f"if(1) {body} /* loop→if(1) */"
            return block

        loop_pattern = re.compile(
            r"(while|for|do)\s*\([^)]*\)\s*\{[^{}]*\}", re.DOTALL
        )
        return loop_pattern.sub(replace_loop, source)

    def _apply_type_level_stubs(
        self, source: str, accessed_fields: list[str]
    ) -> str:
        """Redefine structs with only the accessed fields.

        This is a best-effort transformation: it strips unknown fields from
        struct definitions to avoid transitive dependency errors.

        Args:
            source: C source code string.
            accessed_fields: Field names actually accessed in the slice.

        Returns:
            Modified source (unchanged if no struct definitions found).
        """
        struct_pattern = re.compile(
            r"(typedef\s+)?struct\s+\w*\s*\{([^}]*)\}(\s*\w+)?\s*;",
            re.DOTALL,
        )

        def filter_fields(m: re.Match) -> str:
            prefix = m.group(1) or ""
            body = m.group(2)
            suffix = m.group(3) or ""
            field_lines = []
            for line in body.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                    field_lines.append(line)
                    continue
                # Keep field if any accessed_fields name appears in it
                if any(f in line for f in accessed_fields) or not accessed_fields:
                    field_lines.append(line)
                # Always keep at least a placeholder to avoid empty structs
            filtered_body = "\n".join(field_lines) if field_lines else "\n    int _placeholder;\n"
            return f"{prefix}struct {{\n{filtered_body}\n}}{suffix};"

        return struct_pattern.sub(filter_fields, source)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate(self, code: str) -> None:
        """Basic structural validation.

        Raises:
            ValueError: On missing structural elements.
        """
        if self.spec.entrypoint not in code:
            raise ValueError(
                f"Slice missing entry function '{self.spec.entrypoint}'."
            )
        if "SPINE_PROBE" not in code:
            raise ValueError(
                "Slice missing SPINE_PROBE coverage probes (required by SEDiagnoser)."
            )


def _extract_c_block(text: str) -> str:
    """Extract the first ```c ... ``` block from LLM output."""
    if "```c" in text:
        return text.split("```c")[1].split("```")[0].strip()
    if "```" in text:
        return text.split("```")[1].split("```")[0].strip()
    return text.strip()
