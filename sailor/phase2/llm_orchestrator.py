"""Phase 2 — LLMOrchestrator: Algorithm 1 main loop."""

from __future__ import annotations

import datetime
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sailor.models.schemas import (
    HarnessArtifacts,
    Phase2Result,
    SEOutcome,
    VulnerabilitySpec,
    WitnessInput,
)
from sailor.phase2.compile_diagnoser import CompileDiagnoser
from sailor.phase2.driver_synthesizer import DriverSynthesizer
from sailor.phase2.harness_refiner import HarnessRefiner
from sailor.phase2.se_diagnoser import SEDiagnoser
from sailor.phase2.source_explorer import SourceExplorer
from sailor.phase2.stub_synthesizer import StubSynthesizer

logger = logging.getLogger("sailor.phase2.llm_orchestrator")


@dataclass
class Phase2Config:
    """Configuration for a Phase 2 pipeline run.

    Attributes:
        project_name: Short identifier for the analysed project.
        project_root: Absolute path to the project source root.
        output_dir: Directory where Phase 2 output files are written.
        llm_model: Anthropic Claude model name used for LLM calls.
        llm_api_key: API key injected at runtime (reads ANTHROPIC_API_KEY if empty).
        docker_runner: When provided, compile_harness() and run_klee() are
            delegated to this :class:`~sailor.infra.docker_runner.DockerRunner`
            instance.  When ``None``, the local subprocess fallback is used.
        klee_path: Path or name of the klee executable (local fallback only).
        clang_path: Path or name of the clang executable (local fallback only).
        llvm_link_path: Path or name of the llvm-link executable (local fallback).
        klee_timeout: Maximum KLEE wall-clock time in seconds.
        klee_depth_limit: Maximum KLEE path depth.
        use_docker_klee: Run KLEE inside the klee/klee Docker container (local
            fallback; ignored when docker_runner is set).
        T_explore: Turn budget for source exploration phase.
        T_author: Turn budget for harness authoring phase (T_explore < t < T_author).
        T_max: Total turn budget.
        R_max: Maximum refinement iterations after SITE_REACHED.
    """

    project_name: str
    project_root: Path
    output_dir: Path

    # LLM settings — uses the Anthropic Claude SDK
    llm_model: str = "claude-sonnet-4-6"
    llm_api_key: str = ""  # reads ANTHROPIC_API_KEY if empty

    # DockerRunner for container-based compile/KLEE (None → local subprocess)
    docker_runner: Any = None

    # Injected LLM client (e.g. MockLLMClient for e2e tests).
    # When set, _call_llm() delegates to client.chat() instead of Anthropic SDK.
    llm_client: Any = None

    # Local fallback KLEE/clang settings (used when docker_runner is None)
    klee_path: str = "klee"
    clang_path: str = "clang-14"
    llvm_link_path: str = "llvm-link-14"
    klee_timeout: int = 300
    klee_depth_limit: int = 1000
    use_docker_klee: bool = False

    # KLEE header include path (directory containing klee/klee.h)
    klee_include_path: str = "/tmp/klee_include"

    # Turn budgets (from paper)
    T_explore: int = 8
    T_author: int = 12
    T_max: int = 60
    R_max: int = 15

    # Optional project-specific hints injected into the system prompt.
    driver_hints: list = field(default_factory=list)

    # Maximum tokens in LLM response (lower = less TPM usage, faster rate recovery)
    max_output_tokens: int = 4096

    def __post_init__(self) -> None:
        self.project_root = Path(self.project_root).resolve()
        self.output_dir = Path(self.output_dir).resolve()


class LLMOrchestrator:
    """Implement Algorithm 1: the full LLM-orchestrated symbolic-execution loop.

    Manages turn counter, conversation history, and phase transitions.
    All LLM calls route through :meth:`_call_llm`.

    Args:
        config: A :class:`Phase2Config` instance.
        spec: The :class:`VulnerabilitySpec` to process.
    """

    def __init__(self, config: Phase2Config, spec: VulnerabilitySpec) -> None:
        self.config = config
        self.spec = spec
        self._spec_output_dir = config.output_dir / spec.entrypoint
        self._spec_output_dir.mkdir(parents=True, exist_ok=True)

        self._source_explorer = SourceExplorer(config.project_root)
        self._compile_diagnoser = CompileDiagnoser(
            clang_path=config.clang_path,
            llvm_link_path=config.llvm_link_path,
            project_root=config.project_root,
            output_dir=self._spec_output_dir,
            extra_include_paths=list(spec.build_context.include_paths),
            klee_include_path=config.klee_include_path,
            use_docker=config.use_docker_klee,
            docker_runner=config.docker_runner,
        )
        self._se_diagnoser = SEDiagnoser(
            klee_path=config.klee_path,
            timeout=config.klee_timeout,
            depth_limit=config.klee_depth_limit,
            output_dir=self._spec_output_dir,
            use_docker=config.use_docker_klee,
            docker_runner=config.docker_runner,
        )
        self._harness_refiner = HarnessRefiner(
            r_max=config.R_max,
            spec=spec,
            compile_diagnoser=self._compile_diagnoser,
            se_diagnoser=self._se_diagnoser,
        )

    def run(self) -> Phase2Result:
        """Execute Algorithm 1 in full.

        Returns:
            A :class:`Phase2Result` with the terminal outcome.
        """
        cfg = self.config
        spec = self.spec
        spec_id = f"{spec.rule_id}:{spec.file}:{spec.line}"

        t = 0
        refine_count = 0
        history: list[dict] = [{"role": "system", "content": self._build_system_prompt()}]

        # Cache exploration data
        call_chain: list[str] = []
        guard_conditions = []
        field_classifications = []
        harness: HarnessArtifacts | None = None
        last_se_diag = None

        logger.info(
            "Starting Algorithm 1 for spec=%s (T_max=%d)", spec_id, cfg.T_max
        )

        while t < cfg.T_max:
            # ── Source exploration phase ────────────────────────────────
            if t < cfg.T_explore:
                action_prompt = self._build_exploration_prompt(t)
                history.append({"role": "user", "content": action_prompt})
                llm_response = self._call_llm(history)
                history.append({"role": "assistant", "content": llm_response})

                # Parse tool calls from LLM response and execute them
                tool_results = self._execute_exploration_tools(llm_response)
                if tool_results:
                    history.append({"role": "user", "content": tool_results})
                    # Accumulate exploration data
                    if not call_chain:
                        call_chain = self._source_explorer.get_call_chain(
                            spec.entrypoint, spec.file.split("/")[-1].replace(".c", "")
                        )
                    if not guard_conditions:
                        guard_conditions = self._source_explorer.identify_guards(call_chain)
                    if not field_classifications and spec.pointer_vars:
                        field_classifications = self._source_explorer.classify_fields(
                            spec, spec.pointer_vars[0] if spec.pointer_vars else ""
                        )

                t += 1
                continue

            # ── Harness authoring phase ─────────────────────────────────
            if t < cfg.T_author:
                if harness is None:
                    action_prompt = self._build_authoring_prompt(t, call_chain)
                    history.append({"role": "user", "content": action_prompt})
                    llm_response = self._call_llm(history)
                    history.append({"role": "assistant", "content": llm_response})

                    harness = self._parse_harness_from_response(
                        llm_response, call_chain, guard_conditions, field_classifications
                    )

                t += 1
                continue

            # ── Harness refinement phase ────────────────────────────────
            if harness is None:
                logger.warning("No harness generated after authoring phase — aborting.")
                break

            harness, se_diag, t, refine_count = self._harness_refiner.refine(
                harness, history, t, refine_count, call_chain=call_chain or None
            )
            last_se_diag = se_diag

            if se_diag is not None and se_diag.outcome == SEOutcome.BUG_TRIGGERED:
                logger.info("BUG_TRIGGERED at turn %d", t)
                witness = WitnessInput(
                    spec_id=spec_id,
                    ktest_paths=se_diag.ktest_paths,
                    outcome=SEOutcome.BUG_TRIGGERED,
                    harness=harness,
                    turns_used=t,
                    refine_count=refine_count,
                )
                return Phase2Result(
                    spec_id=spec_id,
                    outcome=SEOutcome.BUG_TRIGGERED,
                    witness=witness,
                    turns_used=t,
                    timestamp=_now(),
                )

            if se_diag is not None and se_diag.outcome == SEOutcome.SITE_REACHED:
                if refine_count > cfg.R_max:
                    logger.info(
                        "R_max=%d exceeded (refine_count=%d) — LIKELY_FP", cfg.R_max, refine_count
                    )
                    return Phase2Result(
                        spec_id=spec_id,
                        outcome=SEOutcome.LIKELY_FP,
                        turns_used=t,
                        timestamp=_now(),
                    )

            # Ask LLM to revise harness based on feedback in history
            if t < cfg.T_max:
                refine_prompt = (
                    "Based on the feedback above, revise the driver and slice. "
                    "Output the updated ```c driver code block``` first, "
                    "then the updated ```c slice code block```."
                )
                history.append({"role": "user", "content": refine_prompt})
                llm_response = self._call_llm(history)
                history.append({"role": "assistant", "content": llm_response})
                harness = self._update_harness_from_response(llm_response, harness)

        logger.info("T_max=%d reached — INCONCLUSIVE", cfg.T_max)
        return Phase2Result(
            spec_id=spec_id,
            outcome=SEOutcome.INCONCLUSIVE,
            turns_used=t,
            timestamp=_now(),
        )

    def _call_llm(self, history: list[dict]) -> str:
        """Call the LLM with the current conversation history.

        When ``config.llm_client`` is set (e.g. MockLLMClient), delegates
        to ``client.chat()``.  Otherwise uses the Anthropic SDK with prompt
        caching on the system message.

        Args:
            history: Ordered list of ``{"role": ..., "content": ...}`` dicts.

        Returns:
            The LLM's response text.

        Raises:
            RuntimeError: If the LLM call fails.
        """
        # Split history into system message and user/assistant turns
        system_msg = ""
        messages: list[dict] = []
        for msg in history:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                messages.append({"role": msg["role"], "content": msg["content"]})

        # Ensure the conversation ends with a user turn
        if not messages or messages[-1]["role"] != "user":
            messages.append({"role": "user", "content": "Continue."})

        # Use injected client (e.g. MockLLMClient) if provided
        if self.config.llm_client is not None:
            return self.config.llm_client.chat(
                messages=messages,
                system_prompt=system_msg,
                max_tokens=self.config.max_output_tokens,
            )

        # Otherwise use Anthropic SDK
        import time as _time
        import anthropic

        api_key = self.config.llm_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY environment variable is not set and "
                "Phase2Config.llm_api_key is empty."
            )

        client = anthropic.Anthropic(api_key=api_key)

        max_retries = 6
        for attempt in range(max_retries):
            try:
                response = client.messages.create(
                    model=self.config.llm_model,
                    max_tokens=self.config.max_output_tokens,
                    system=[{
                        "type": "text",
                        "text": system_msg,
                        "cache_control": {"type": "ephemeral"},
                    }] if system_msg else anthropic.NOT_GIVEN,
                    messages=messages,
                )
                return response.content[0].text if response.content else ""
            except anthropic.RateLimitError as exc:
                delay = 60 * (attempt + 1)
                logger.warning(
                    "LLM rate-limited — retrying in %ds (attempt %d/%d).",
                    delay, attempt + 1, max_retries,
                )
                if attempt < max_retries - 1:
                    _time.sleep(delay)
                    continue
                raise RuntimeError(f"LLM call failed: {exc}") from exc
            except anthropic.APIStatusError as exc:
                if exc.status_code in (529, 503) and attempt < max_retries - 1:
                    delay = 60 * (attempt + 1)
                    logger.warning(
                        "LLM overloaded (%d) — retrying in %ds (attempt %d/%d).",
                        exc.status_code, delay, attempt + 1, max_retries,
                    )
                    _time.sleep(delay)
                    continue
                logger.error("LLM call failed: %s", exc)
                raise RuntimeError(f"LLM call failed: {exc}") from exc
            except Exception as exc:
                logger.error("LLM call failed: %s", exc)
                raise RuntimeError(f"LLM call failed: {exc}") from exc
        raise RuntimeError("LLM call failed: max retries exceeded")

    def _build_system_prompt(self) -> str:
        """Construct the system prompt sent at the start of every conversation.

        Returns:
            System prompt string containing the spec, rules, and tool definitions.
        """
        spec = self.spec

        hints_section = ""
        if self.config.driver_hints:
            hints_str = "\n".join(f"  - {h}" for h in self.config.driver_hints)
            hints_section = f"\n=== PROJECT-SPECIFIC HINTS ===\n{hints_str}\n"

        return f"""You are an expert symbolic-execution harness engineer using KLEE.
Your task is to determine whether the following vulnerability is reachable and triggerable.

=== VULNERABILITY SPEC ===
rule_id:            {spec.rule_id}
cwe:                {spec.cwe}
file:               {spec.file}
line:               {spec.line}
entry function:     {spec.entrypoint}
description:        {spec.message}
snippet:            {spec.snippet}
assertion template: {spec.assertion_template}
suspect_calls:      {', '.join(spec.suspect_calls) or 'none'}
length_vars:        {', '.join(spec.length_vars) or 'none'}
pointer_vars:       {', '.join(spec.pointer_vars) or 'none'}

=== YOUR GOAL ===
1. Explore source (turns 0-{self.config.T_explore-1}): learn signatures, types, call chain.
2. Author harness (turns {self.config.T_explore}-{self.config.T_author-1}): write driver + code slice.
3. Refine (turns {self.config.T_author}+): fix compile/SE errors until bug triggered or budget exhausted.
{hints_section}
=== HARNESS RULES ===
- The harness MUST be self-contained: do NOT include any project headers (e.g. netdissect.h,
  pcap.h, bootp.h). Those headers have external library dependencies that are unavailable.
- Define all required structs and types directly in the slice file.
- The driver includes only <klee/klee.h> and <stdlib.h>/<string.h>.
- Use klee_make_symbolic() for all inputs. Use klee_assume() for constraint injection.

=== OUTPUT FORMAT ===
When asked to produce code, output:
  Driver: a ```c ... ``` block with the int main() driver.
  Slice:  a ```c ... ``` block with the code slice + stubs.
Do NOT include prose between or after the code blocks.
"""

    # ------------------------------------------------------------------
    # Phase-specific prompt builders
    # ------------------------------------------------------------------

    def _build_exploration_prompt(self, t: int) -> str:
        spec = self.spec
        return (
            f"[Turn {t} — Source Exploration]\n"
            f"Explore the project source to understand the call chain from "
            f"'{spec.entrypoint}' to {spec.file}:{spec.line}.\n\n"
            f"Request any of the following information you need:\n"
            f"  - Function signature for: {spec.entrypoint}\n"
            f"  - Struct definitions for types used by: {spec.entrypoint}\n"
            f"  - Source slice: {spec.file} lines around {spec.line}\n"
            f"  - Call chain from {spec.entrypoint} to the vulnerable function\n\n"
            f"State which information you need and I will retrieve it."
        )

    def _build_authoring_prompt(self, t: int, call_chain: list[str]) -> str:
        chain_str = " → ".join(call_chain) if call_chain else self.spec.entrypoint
        return (
            f"[Turn {t} — Harness Authoring]\n"
            f"Now write the complete KLEE harness.\n\n"
            f"Call chain: {chain_str}\n\n"
            f"Produce TWO code blocks:\n"
            f"1. ```c driver code (contains int main()) ```\n"
            f"2. ```c slice code (contains {self.spec.entrypoint} and all stubs) ```\n\n"
            f"Requirements:\n"
            f"- Driver: klee_make_symbolic all inputs, klee_assume all guards,\n"
            f"  calloc all pointer fields, call {self.spec.entrypoint}.\n"
            f"- Slice: all 4 stub granularities (function/branch/loop/type),\n"
            f"  SPINE_PROBE at every function entry,\n"
            f"  klee_assert(0 && \"SAILOR_SINK_REACHED\") after line {self.spec.line}.\n"
            f"- CWE-specific: {self.spec.assertion_template}"
        )

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _execute_exploration_tools(self, llm_response: str) -> str:
        """Execute source-reading tool calls requested by the LLM.

        Parses the response for function/struct/file lookup requests and
        executes them via SourceExplorer.

        Args:
            llm_response: Raw LLM response text.

        Returns:
            Tool results as a formatted string for the next history entry.
        """
        results: list[str] = []

        # Function signature requests
        for m in re.finditer(r"function signature (?:for )?['\"`]?(\w+)['\"`]?", llm_response, re.I):
            name = m.group(1)
            sig = self._source_explorer.get_function_signature(name)
            results.append(f"=== Signature: {name} ===\n{sig}")

        # Struct definition requests
        for m in re.finditer(r"struct (?:definition )?(?:for )?['\"`]?(\w+)['\"`]?", llm_response, re.I):
            name = m.group(1)
            defn = self._source_explorer.get_struct_definition(name)
            results.append(f"=== Struct: {name} ===\n{defn}")

        # File slice requests
        for m in re.finditer(r"(?:source|lines?) (?:at|from) (\S+):?(\d+)(?:-(\d+))?", llm_response, re.I):
            fpath, start_str, end_str = m.group(1), m.group(2), m.group(3)
            start = int(start_str)
            end = int(end_str) if end_str else start + 30
            slc = self._source_explorer.get_file_slice(fpath, max(1, start - 10), end + 10)
            results.append(f"=== File slice {fpath}:{start}-{end} ===\n{slc}")

        # Always fetch the vulnerable site if not yet done in first exploration turn
        if not results:
            sig = self._source_explorer.get_function_signature(self.spec.entrypoint)
            slc = self._source_explorer.get_file_slice(
                self.spec.file,
                max(1, self.spec.line - 15),
                self.spec.line + 15,
            )
            results.append(f"=== Signature: {self.spec.entrypoint} ===\n{sig}")
            results.append(f"=== Vulnerable site {self.spec.file}:{self.spec.line} ===\n{slc}")

        return "\n\n".join(results)

    def _parse_harness_from_response(
        self,
        llm_response: str,
        call_chain: list[str],
        guard_conditions: list,
        field_classifications: list,
    ) -> HarnessArtifacts:
        """Parse driver and slice C code from an LLM authoring response.

        Falls back to synthesizer-generated defaults if the response cannot
        be parsed.

        Args:
            llm_response: Raw LLM response containing code blocks.
            call_chain: Resolved call chain.
            guard_conditions: Guard conditions for driver synthesis.
            field_classifications: Field classifications for driver synthesis.

        Returns:
            A :class:`HarnessArtifacts` instance.
        """
        driver_syn = DriverSynthesizer(self.spec, field_classifications, guard_conditions)
        stub_syn = StubSynthesizer(self.spec, self._source_explorer, call_chain or [self.spec.entrypoint])

        # Extract all ```c ... ``` blocks
        c_blocks = re.findall(r"```c(.*?)```", llm_response, re.DOTALL)
        driver_c = c_blocks[0].strip() if len(c_blocks) >= 1 else ""
        slice_c = c_blocks[1].strip() if len(c_blocks) >= 2 else ""

        # Validate or use synthesizer defaults
        if not driver_c or self.spec.entrypoint not in driver_c:
            logger.warning("Driver parse failed — using synthesizer prompt as fallback.")
            driver_c = self._generate_minimal_driver(guard_conditions, field_classifications)

        if not slice_c or self.spec.entrypoint not in slice_c:
            logger.warning("Slice parse failed — using minimal stub.")
            slice_c = self._generate_minimal_slice(call_chain)

        # Inject SAILOR_SINK_REACHED if not present
        slice_c = stub_syn.inject_reachability_assertion(slice_c)

        # Apply vulnerability constraints to driver
        driver_c = driver_syn.add_vulnerability_condition(driver_c, self.spec)

        harness_dir = self._spec_output_dir / "harness"
        return HarnessArtifacts(
            driver_c=driver_c,
            slice_c=slice_c,
            compile_cmd=self._compile_diagnoser.get_compile_cmd(
                str(harness_dir / "driver.c"), str(harness_dir / "driver.bc")
            ),
            link_cmd=self._compile_diagnoser.get_link_cmd(
                str(harness_dir / "driver.bc"),
                str(harness_dir / "slice.bc"),
                str(harness_dir / "harness.bc"),
            ),
            bitcode_path=None,
        )

    def _update_harness_from_response(
        self, llm_response: str, current: HarnessArtifacts
    ) -> HarnessArtifacts:
        """Update driver and/or slice from a refinement LLM response.

        Args:
            llm_response: Raw LLM refinement response.
            current: Current harness artefacts to fall back to on parse failure.

        Returns:
            Updated :class:`HarnessArtifacts`.
        """
        c_blocks = re.findall(r"```c(.*?)```", llm_response, re.DOTALL)
        driver_c = c_blocks[0].strip() if len(c_blocks) >= 1 else current.driver_c
        slice_c = c_blocks[1].strip() if len(c_blocks) >= 2 else current.slice_c

        if not driver_c:
            driver_c = current.driver_c
        if not slice_c:
            slice_c = current.slice_c

        return current.model_copy(
            update={"driver_c": driver_c, "slice_c": slice_c, "bitcode_path": None}
        )

    # ------------------------------------------------------------------
    # Minimal fallback generators
    # ------------------------------------------------------------------

    def _generate_minimal_driver(
        self, guard_conditions: list, field_classifications: list
    ) -> str:
        """Generate a minimal valid driver as a fallback."""
        spec = self.spec
        assume_stmts = "\n    ".join(g.assume_stmt for g in guard_conditions)
        return f"""#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration */
void {spec.entrypoint}(void *ctx);

int main(void) {{
    unsigned char buf[64];
    klee_make_symbolic(buf, sizeof(buf), "buf");
    {assume_stmts}
    {spec.entrypoint}(buf);
    return 0;
}}
"""

    def _generate_minimal_slice(self, call_chain: list[str]) -> str:
        """Generate a minimal valid slice as a fallback."""
        spec = self.spec
        chain_str = " → ".join(call_chain) if call_chain else spec.entrypoint
        return f"""#include <klee/klee.h>
#include <stdlib.h>

/* Minimal slice for call chain: {chain_str} */

void {spec.entrypoint}(void *ctx) {{
    klee_warning_once("SPINE_PROBE:{spec.entrypoint}:ENTRY");
    /* TODO: LLM must replace this with real implementation */
    klee_assert(0 && "SAILOR_SINK_REACHED");
}}
"""


def _now() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
