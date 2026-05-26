"""Phase 2 — HarnessRefiner: compile-execute-refine feedback loop."""

from __future__ import annotations

import logging

from sailor.models.schemas import (
    CompileDiagnostic,
    HarnessArtifacts,
    SEDiagnostic,
    SEOutcome,
    VulnerabilitySpec,
)
from sailor.phase2.compile_diagnoser import CompileDiagnoser
from sailor.phase2.se_diagnoser import SEDiagnoser

logger = logging.getLogger("sailor.phase2.harness_refiner")


class HarnessRefiner:
    """Manage one iteration of the compile → KLEE → diagnose → feedback loop.

    Args:
        r_max: Maximum number of refinement iterations after SITE_REACHED.
        spec: The :class:`VulnerabilitySpec` being processed.
        compile_diagnoser: A :class:`CompileDiagnoser` instance.
        se_diagnoser: A :class:`SEDiagnoser` instance.
    """

    def __init__(
        self,
        r_max: int,
        spec: VulnerabilitySpec,
        compile_diagnoser: CompileDiagnoser,
        se_diagnoser: SEDiagnoser,
    ) -> None:
        self.r_max = r_max
        self.spec = spec
        self.compile_diagnoser = compile_diagnoser
        self.se_diagnoser = se_diagnoser

    def refine(
        self,
        harness: HarnessArtifacts,
        history: list[dict],
        t: int,
        refine_count: int,
        call_chain: list[str] | None = None,
    ) -> tuple[HarnessArtifacts, SEDiagnostic | None, int, int]:
        """Execute one iteration of the compile-execute-refine loop.

        Args:
            harness: Current harness artefacts.
            history: LLM conversation history (mutated in-place with feedback).
            t: Current turn counter.
            refine_count: Number of completed refinement iterations.
            call_chain: Expected function call chain used to compute which functions
                were missed by KLEE's coverage probes.

        Returns:
            ``(harness, se_diag, t+1, refine_count)`` where ``se_diag`` is
            ``None`` when compilation failed, and the :class:`SEDiagnostic`
            on SE completion.
        """
        # Step 1 — Compile
        success, compile_diag = self.compile_diagnoser.compile(
            harness.driver_c, harness.slice_c
        )
        if not success:
            feedback = self._build_compile_feedback(compile_diag)
            history.append(feedback)
            logger.info("Turn %d: compile failed [%s]", t, compile_diag.error_class)
            return harness, None, t + 1, refine_count

        # Update artefacts with bitcode path now that compilation succeeded
        harness = harness.model_copy(
            update={"bitcode_path": self.compile_diagnoser.get_harness_bc_path()}
        )

        # Step 2 — Run KLEE
        se_diag = self.se_diagnoser.run(harness.bitcode_path)
        logger.info("Turn %d: SE outcome=%s", t, se_diag.outcome.value)

        # Compute which call-chain functions were NOT entered (paper §4.4 not_reached feedback)
        if call_chain:
            missed = [f for f in call_chain if f not in se_diag.functions_entered]
            se_diag = se_diag.model_copy(update={"functions_missed": missed})

        if se_diag.outcome == SEOutcome.BUG_TRIGGERED:
            # Caller terminates the loop
            return harness, se_diag, t + 1, refine_count

        if se_diag.outcome == SEOutcome.SITE_REACHED:
            refine_count += 1
            feedback = self._build_se_feedback(se_diag)
            history.append(feedback)
            return harness, se_diag, t + 1, refine_count

        # NOT_REACHED (or INCONCLUSIVE)
        feedback = self._build_se_feedback(se_diag)
        history.append(feedback)
        return harness, se_diag, t + 1, refine_count

    # ------------------------------------------------------------------
    # Feedback builders
    # ------------------------------------------------------------------

    def _build_compile_feedback(self, diag: CompileDiagnostic) -> dict:
        """Format a CompileDiagnostic as an LLM history entry.

        Args:
            diag: The compilation diagnostic to format.

        Returns:
            A dict suitable for appending to the LLM history list.
        """
        parts = [
            f"COMPILE ERROR [{diag.error_class.value}]",
            f"Raw error:\n{diag.raw_error[:1500]}",
            f"Suggested fix: {diag.suggested_fix}",
        ]
        if diag.relevant_source:
            parts.append(f"Relevant source:\n{diag.relevant_source}")
        return {
            "role": "user",
            "content": "\n\n".join(parts),
        }

    def _build_se_feedback(self, diag: SEDiagnostic) -> dict:
        """Format a SEDiagnostic as an LLM history entry.

        For NOT_REACHED: includes probe analysis.
        For SITE_REACHED: suggests tightening klee_assume constraints.

        Args:
            diag: The SE diagnostic to format.

        Returns:
            A dict suitable for appending to the LLM history list.
        """
        if diag.outcome == SEOutcome.SITE_REACHED:
            content = (
                f"SE RESULT: SITE_REACHED — the vulnerable site was executed, "
                f"but no memory error was triggered.\n\n"
                f"Action required: Tighten the klee_assume constraints in the "
                f"driver to force the vulnerability condition.\n"
                f"For {self.spec.cwe}, ensure the constraint in "
                f"add_vulnerability_condition() is correctly applied.\n\n"
                f"Functions entered: {', '.join(diag.functions_entered) or 'none'}"
            )
        elif diag.outcome == SEOutcome.NOT_REACHED:
            entered = ", ".join(diag.functions_entered) or "none"
            missed = ", ".join(diag.functions_missed) or "none"
            content = (
                f"SE RESULT: NOT_REACHED — the vulnerable site was never executed.\n\n"
                f"Coverage probe analysis:\n"
                f"  Entered: {entered}\n"
                f"  Missed:  {missed}\n\n"
                f"Action required:\n"
                f"  1. Check driver guard negations — add klee_assume to bypass missed guards.\n"
                f"  2. Check stub return values for functions before missed functions.\n"
                f"     Stubs that return 0/NULL may cause the call chain to abort early.\n"
                f"  3. Verify the entry function call in main() passes correctly typed args."
            )
        else:
            content = (
                f"SE RESULT: {diag.outcome.value}\n"
                f"Raw output (truncated):\n{diag.raw_output[:1000]}"
            )

        return {"role": "user", "content": content}
