"""Unit tests for sailor/phase2/ — Phase 2: LLM-Orchestrated Symbolic Execution."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sailor.models.schemas import (
    BuildContext,
    CompileDiagnostic,
    CompileErrorClass,
    FieldClassification,
    GuardCondition,
    HarnessArtifacts,
    SEDiagnostic,
    SEOutcome,
    SymbolicInputKind,
    VulnerabilitySpec,
)
from sailor.phase2.compile_diagnoser import CompileDiagnoser
from sailor.phase2.driver_synthesizer import DriverSynthesizer
from sailor.phase2.harness_refiner import HarnessRefiner
from sailor.phase2.llm_orchestrator import LLMOrchestrator, Phase2Config
from sailor.phase2.se_diagnoser import SEDiagnoser
from sailor.phase2.source_explorer import SourceExplorer
from sailor.phase2.stub_synthesizer import StubSynthesizer


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def minimal_spec() -> VulnerabilitySpec:
    """A minimal VulnerabilitySpec for testing."""
    return VulnerabilitySpec(
        rule_id="cpp/cwe-120/buffer-overflow",
        cwe="CWE-120",
        file="src/foo.c",
        line=42,
        col=1,
        entrypoint="foo_process",
        message="Unchecked buffer copy length",
        snippet="memcpy(dst, src, n);",
        assertion_template="n <= min(len(dst), len(src))",
        suspect_calls=["memcpy"],
        length_vars=["n"],
        pointer_vars=["dst", "src"],
        build_context=BuildContext(include_paths=[], defines=[]),
    )


@pytest.fixture()
def spec_cwe416() -> VulnerabilitySpec:
    """A VulnerabilitySpec for CWE-416 (use-after-free)."""
    return VulnerabilitySpec(
        rule_id="cpp/cwe-416/use-after-free",
        cwe="CWE-416",
        file="src/alloc.c",
        line=99,
        col=1,
        entrypoint="obj_release",
        message="Use after free",
        snippet="obj->data;",
        assertion_template="no use of p after free(p)",
        suspect_calls=["free"],
        length_vars=[],
        pointer_vars=["obj"],
        build_context=BuildContext(),
    )


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """Create a minimal project directory with one C source file."""
    src = tmp_path / "foo.c"
    src.write_text(
        "int foo_process(char *dst, const char *src, int n) {\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    return tmp_path


# ===========================================================================
# SourceExplorer — pure-logic helpers
# ===========================================================================

class TestSourceExplorerNegateGuard:
    """Tests for SourceExplorer._negate_guard() static method."""

    def test_negate_null_check(self) -> None:
        assert SourceExplorer._negate_guard("ptr == NULL") == "ptr != NULL"

    def test_negate_not_null_check(self) -> None:
        assert SourceExplorer._negate_guard("ptr != NULL") == "ptr == NULL"

    def test_negate_negated_expr(self) -> None:
        # !expr → strip leading ! → return the bare expr
        assert SourceExplorer._negate_guard("!valid") == "valid"

    def test_negate_other_expr(self) -> None:
        result = SourceExplorer._negate_guard("count > 0")
        assert result == "!(count > 0)"

    def test_leading_not_stripped(self) -> None:
        result = SourceExplorer._negate_guard("!p == NULL")
        # strips leading !, then sees no NULL → wraps
        assert "p == NULL" in result or "p" in result


class TestSourceExplorerParseStructFields:
    """Tests for SourceExplorer._parse_struct_fields() static method."""

    def test_basic_fields(self) -> None:
        struct_text = (
            "struct foo {\n"
            "    int count;\n"
            "    char *name;\n"
            "    size_t len;\n"
            "};\n"
        )
        fields = SourceExplorer._parse_struct_fields(struct_text)
        names = [f[1] for f in fields]
        assert "count" in names
        assert "name" in names
        assert "len" in names

    def test_skips_keywords(self) -> None:
        struct_text = "struct foo {\n    return 0;\n    if cond;\n    int x;\n};\n"
        fields = SourceExplorer._parse_struct_fields(struct_text)
        names = [f[1] for f in fields]
        assert "x" in names
        # keywords should be filtered out
        assert "0" not in names

    def test_empty_struct(self) -> None:
        fields = SourceExplorer._parse_struct_fields("struct foo {};\n")
        assert fields == []


class TestSourceExplorerGetFileSlice:
    """Tests for SourceExplorer.get_file_slice()."""

    def test_returns_lines(self, tmp_project: Path) -> None:
        explorer = SourceExplorer(tmp_project)
        result = explorer.get_file_slice("foo.c", 1, 3)
        assert "foo_process" in result

    def test_file_not_found(self, tmp_project: Path) -> None:
        explorer = SourceExplorer(tmp_project)
        result = explorer.get_file_slice("missing.c", 1, 5)
        assert "not found" in result.lower()

    def test_line_numbering(self, tmp_project: Path) -> None:
        explorer = SourceExplorer(tmp_project)
        result = explorer.get_file_slice("foo.c", 1, 1)
        assert result.startswith("1:")


# ===========================================================================
# DriverSynthesizer — vulnerability constraint generation
# ===========================================================================

class TestDriverSynthesizerConstraints:
    """Tests for DriverSynthesizer._build_vulnerability_constraint()."""

    def _make_spec(self, cwe: str, length_vars: list[str], pointer_vars: list[str]) -> VulnerabilitySpec:
        return VulnerabilitySpec(
            rule_id=f"cpp/{cwe.lower()}/test",
            cwe=cwe,
            file="f.c",
            line=1,
            col=1,
            entrypoint="entry",
            message="test",
            snippet="x;",
            assertion_template="n <= len(dst)",
            suspect_calls=[],
            length_vars=length_vars,
            pointer_vars=pointer_vars,
            build_context=BuildContext(),
        )

    def test_cwe120_constraint(self) -> None:
        spec = self._make_spec("CWE-120", ["n"], ["dst"])
        result = DriverSynthesizer._build_vulnerability_constraint(spec)
        assert "klee_assume" in result
        assert "n" in result

    def test_cwe416_constraint(self) -> None:
        spec = self._make_spec("CWE-416", [], ["obj"])
        result = DriverSynthesizer._build_vulnerability_constraint(spec)
        assert "free(" in result
        assert "obj" in result

    def test_cwe476_constraint(self) -> None:
        spec = self._make_spec("CWE-476", [], ["ptr"])
        result = DriverSynthesizer._build_vulnerability_constraint(spec)
        assert "klee_assume" in result
        assert "NULL" in result

    def test_cwe190_constraint(self) -> None:
        spec = self._make_spec("CWE-190", ["n"], [])
        result = DriverSynthesizer._build_vulnerability_constraint(spec)
        assert "klee_assume" in result
        assert "0x7fffffff" in result

    def test_unknown_cwe_returns_empty(self) -> None:
        spec = self._make_spec("CWE-999", [], [])
        result = DriverSynthesizer._build_vulnerability_constraint(spec)
        assert result == ""


class TestDriverSynthesizerValidation:
    """Tests for DriverSynthesizer._validate()."""

    def test_valid_driver(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = DriverSynthesizer(minimal_spec, [], [])
        code = "int main() { klee_make_symbolic(&x, 4, \"x\"); foo_process(); return 0; }"
        syn._validate(code)  # should not raise

    def test_missing_main(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = DriverSynthesizer(minimal_spec, [], [])
        with pytest.raises(ValueError, match="main"):
            syn._validate("klee_make_symbolic(&x, 4, \"x\"); foo_process();")

    def test_missing_symbolic(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = DriverSynthesizer(minimal_spec, [], [])
        with pytest.raises(ValueError, match="klee_make_symbolic"):
            syn._validate("int main() { foo_process(); return 0; }")

    def test_missing_entrypoint(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = DriverSynthesizer(minimal_spec, [], [])
        with pytest.raises(ValueError, match="foo_process"):
            syn._validate("int main() { klee_make_symbolic(&x, 4, \"x\"); return 0; }")


class TestDriverSynthesizerAddVulnCondition:
    """Tests for DriverSynthesizer.add_vulnerability_condition()."""

    def test_inserts_before_entry_call(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = DriverSynthesizer(minimal_spec, [], [])
        driver = "int main() {\n    foo_process(buf);\n    return 0;\n}"
        result = syn.add_vulnerability_condition(driver, minimal_spec)
        # constraint should appear before foo_process
        ep_idx = result.index("foo_process")
        assert "klee_assume" in result[:ep_idx]

    def test_no_constraint_for_unknown_cwe(self) -> None:
        spec = VulnerabilitySpec(
            rule_id="cpp/cwe-999/test",
            cwe="CWE-999",
            file="f.c",
            line=1,
            col=1,
            entrypoint="entry",
            message="test",
            snippet="x;",
            assertion_template="x is safe",
            suspect_calls=[],
            length_vars=[],
            pointer_vars=[],
            build_context=BuildContext(),
        )
        syn = DriverSynthesizer(spec, [], [])
        driver = "int main() { entry(); return 0; }"
        assert syn.add_vulnerability_condition(driver, spec) == driver


class TestDriverSynthesizerBuildPrompt:
    """Tests for DriverSynthesizer.build_prompt()."""

    def test_prompt_contains_spec_fields(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = DriverSynthesizer(minimal_spec, [], [])
        prompt = syn.build_prompt()
        assert "foo_process" in prompt
        assert "CWE-120" in prompt
        assert "src/foo.c" in prompt
        assert "klee_make_symbolic" in prompt
        assert "klee_assume" in prompt


# ===========================================================================
# StubSynthesizer — slice generation and granularities
# ===========================================================================

class TestStubSynthesizerInjectReachabilityAssertion:
    """Tests for StubSynthesizer.inject_reachability_assertion()."""

    def _make_syn(self, spec: VulnerabilitySpec) -> StubSynthesizer:
        explorer = MagicMock(spec=SourceExplorer)
        return StubSynthesizer(spec, explorer, [spec.entrypoint])

    def test_injects_when_missing(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec)
        slice_c = "void foo_process() {\n    memcpy(dst, src, n);\n}\n"
        result = syn.inject_reachability_assertion(slice_c)
        assert "SAILOR_SINK_REACHED" in result

    def test_noop_when_already_present(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec)
        slice_c = 'void foo() { klee_assert(0 && "SAILOR_SINK_REACHED"); }'
        result = syn.inject_reachability_assertion(slice_c)
        assert result == slice_c

    def test_injects_after_snippet(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec)
        slice_c = "void f() {\n    memcpy(dst, src, n);\n    return;\n}\n"
        result = syn.inject_reachability_assertion(slice_c)
        # SAILOR_SINK_REACHED should follow the snippet
        memcpy_idx = result.index("memcpy")
        sink_idx = result.index("SAILOR_SINK_REACHED")
        assert sink_idx > memcpy_idx


class TestStubSynthesizerFunctionLevelStubs:
    """Tests for StubSynthesizer._apply_function_level_stubs()."""

    def _make_syn(self, spec: VulnerabilitySpec, call_chain: list[str]) -> StubSynthesizer:
        explorer = MagicMock(spec=SourceExplorer)
        return StubSynthesizer(spec, explorer, call_chain)

    def test_on_path_retained(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec, ["foo_process", "memcpy"])
        result = syn._apply_function_level_stubs(["foo_process", "memcpy"], ["foo_process", "memcpy"])
        assert "foo_process" in result
        assert "memcpy" in result

    def test_off_path_gets_stub(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec, ["foo_process"])
        result = syn._apply_function_level_stubs(["foo_process", "helper_fn"], ["foo_process"])
        combined = " ".join(result)
        assert "STUB" in combined or "klee_make_symbolic" in combined

    def test_cwe416_free_calls_real_free(self, spec_cwe416: VulnerabilitySpec) -> None:
        syn = self._make_syn(spec_cwe416, ["obj_release"])
        result = syn._apply_function_level_stubs(["obj_release", "free"], ["obj_release"])
        combined = " ".join(result)
        assert "__real_free" in combined


class TestStubSynthesizerValidation:
    """Tests for StubSynthesizer._validate()."""

    def _make_syn(self, spec: VulnerabilitySpec) -> StubSynthesizer:
        explorer = MagicMock(spec=SourceExplorer)
        return StubSynthesizer(spec, explorer, [spec.entrypoint])

    def test_valid_slice(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec)
        code = ('void foo_process() { klee_warning_once("SPINE_PROBE:foo_process:ENTRY"); }')
        syn._validate(code)  # should not raise

    def test_missing_entrypoint(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec)
        with pytest.raises(ValueError, match="foo_process"):
            syn._validate('void other() { klee_warning_once("SPINE_PROBE:other:ENTRY"); }')

    def test_missing_spine_probe(self, minimal_spec: VulnerabilitySpec) -> None:
        syn = self._make_syn(minimal_spec)
        with pytest.raises(ValueError, match="SPINE_PROBE"):
            syn._validate("void foo_process() { }")


class TestStubSynthesizerBuildPrompt:
    """Tests for StubSynthesizer.build_prompt()."""

    def test_all_four_granularities_documented(self, minimal_spec: VulnerabilitySpec) -> None:
        explorer = MagicMock(spec=SourceExplorer)
        syn = StubSynthesizer(minimal_spec, explorer, ["foo_process"])
        prompt = syn.build_prompt()
        assert "FUNCTION-LEVEL" in prompt
        assert "BRANCH-LEVEL" in prompt
        assert "LOOP-LEVEL" in prompt
        assert "TYPE-LEVEL" in prompt

    def test_cwe416_exception_mentioned(self, minimal_spec: VulnerabilitySpec) -> None:
        explorer = MagicMock(spec=SourceExplorer)
        syn = StubSynthesizer(minimal_spec, explorer, ["foo_process"])
        prompt = syn.build_prompt()
        assert "CWE-416" in prompt
        assert "free()" in prompt or "__real_free" in prompt

    def test_spine_probe_documented(self, minimal_spec: VulnerabilitySpec) -> None:
        explorer = MagicMock(spec=SourceExplorer)
        syn = StubSynthesizer(minimal_spec, explorer, ["foo_process"])
        prompt = syn.build_prompt()
        assert "SPINE_PROBE" in prompt
        assert "klee_warning_once" in prompt


# ===========================================================================
# CompileDiagnoser — error classification
# ===========================================================================

class TestCompileDiagnoserClassifyError:
    """Tests for CompileDiagnoser._classify_error()."""

    @pytest.fixture()
    def diagnoser(self, tmp_path: Path) -> CompileDiagnoser:
        return CompileDiagnoser(
            clang_path="clang-14",
            llvm_link_path="llvm-link-14",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )

    def test_incomplete_type(self, diagnoser: CompileDiagnoser) -> None:
        err = "error: 'struct foo' is an incomplete type"
        diag = diagnoser._classify_error(err)
        assert diag.error_class == CompileErrorClass.INCOMPLETE_TYPE
        assert diag.suggested_fix

    def test_unknown_type_name(self, diagnoser: CompileDiagnoser) -> None:
        err = "error: unknown type name 'uint32_t'"
        diag = diagnoser._classify_error(err)
        assert diag.error_class == CompileErrorClass.INCOMPLETE_TYPE

    def test_conflicting_proto(self, diagnoser: CompileDiagnoser) -> None:
        err = "error: conflicting types for 'bfd_get_32'"
        diag = diagnoser._classify_error(err)
        assert diag.error_class == CompileErrorClass.CONFLICTING_PROTO
        assert "bfd_get_32" in diag.suggested_fix

    def test_redefinition(self, diagnoser: CompileDiagnoser) -> None:
        err = "error: redefinition of 'struct asection'"
        diag = diagnoser._classify_error(err)
        assert diag.error_class == CompileErrorClass.REDEFINITION
        assert "#ifndef" in diag.suggested_fix

    def test_other_error(self, diagnoser: CompileDiagnoser) -> None:
        err = "error: expected ';' before '}'"
        diag = diagnoser._classify_error(err)
        assert diag.error_class == CompileErrorClass.OTHER


# ===========================================================================
# SEDiagnoser — outcome parsing and coverage probes
# ===========================================================================

class TestSEDiagnoserParseCoverageProbes:
    """Tests for SEDiagnoser._parse_coverage_probes()."""

    @pytest.fixture()
    def diagnoser(self, tmp_path: Path) -> SEDiagnoser:
        return SEDiagnoser(
            klee_path="klee",
            timeout=300,
            depth_limit=1000,
            output_dir=tmp_path,
        )

    def test_parses_entered_functions(self, diagnoser: SEDiagnoser) -> None:
        stderr = (
            'KLEE: WARNING ONCE: SPINE_PROBE:foo_process:ENTRY\n'
            'KLEE: WARNING ONCE: SPINE_PROBE:bar_func:ENTRY\n'
        )
        entered, missed = diagnoser._parse_coverage_probes(stderr)
        assert "foo_process" in entered
        assert "bar_func" in entered

    def test_deduplicates_entries(self, diagnoser: SEDiagnoser) -> None:
        stderr = (
            'KLEE: WARNING ONCE: SPINE_PROBE:foo:ENTRY\n'
            'KLEE: WARNING ONCE: SPINE_PROBE:foo:ENTRY\n'
        )
        entered, _ = diagnoser._parse_coverage_probes(stderr)
        assert entered.count("foo") == 1

    def test_returns_empty_missed(self, diagnoser: SEDiagnoser) -> None:
        # functions_missed is computed by HarnessRefiner, not SEDiagnoser
        _, missed = diagnoser._parse_coverage_probes("SPINE_PROBE:foo:ENTRY")
        assert missed == []

    def test_no_probes(self, diagnoser: SEDiagnoser) -> None:
        entered, missed = diagnoser._parse_coverage_probes("KLEE: some other output")
        assert entered == []
        assert missed == []


class TestSEDiagnoserParseOutcome:
    """Tests for SEDiagnoser._parse_outcome()."""

    @pytest.fixture()
    def diagnoser(self, tmp_path: Path) -> SEDiagnoser:
        return SEDiagnoser(
            klee_path="klee",
            timeout=300,
            depth_limit=1000,
            output_dir=tmp_path,
        )

    def test_bug_triggered_memory_error_with_ktest(
        self, diagnoser: SEDiagnoser, tmp_path: Path
    ) -> None:
        klee_out = tmp_path / "klee-last"
        klee_out.mkdir()
        (klee_out / "test000001.ktest").write_bytes(b"")
        outcome = diagnoser._parse_outcome(
            "KLEE: memory error: out of bound pointer",
            "",
            klee_out,
        )
        assert outcome == SEOutcome.BUG_TRIGGERED

    def test_site_reached_sailor_assert_with_ktest(
        self, diagnoser: SEDiagnoser, tmp_path: Path
    ) -> None:
        klee_out = tmp_path / "klee-last"
        klee_out.mkdir()
        (klee_out / "test000001.ktest").write_bytes(b"")
        outcome = diagnoser._parse_outcome(
            "",
            "SAILOR_SINK_REACHED assertion",
            klee_out,
        )
        assert outcome == SEOutcome.SITE_REACHED

    def test_not_reached_no_triggers(
        self, diagnoser: SEDiagnoser, tmp_path: Path
    ) -> None:
        klee_out = tmp_path / "klee-last"
        klee_out.mkdir()
        outcome = diagnoser._parse_outcome("", "", klee_out)
        assert outcome == SEOutcome.NOT_REACHED


class TestSEDiagnoserKleeCmd:
    """Tests for SEDiagnoser._build_klee_cmd()."""

    @pytest.fixture()
    def diagnoser(self, tmp_path: Path) -> SEDiagnoser:
        return SEDiagnoser(
            klee_path="klee",
            timeout=300,
            depth_limit=1000,
            output_dir=tmp_path,
        )

    def test_dual_search_strategies(self, diagnoser: SEDiagnoser) -> None:
        cmd = diagnoser._build_klee_cmd("/tmp/harness.bc", "/tmp/klee-last")
        cmd_str = " ".join(cmd)
        assert "--search=random-path" in cmd_str
        assert "--search=dfs" in cmd_str

    def test_timeout_flag(self, diagnoser: SEDiagnoser) -> None:
        cmd = diagnoser._build_klee_cmd("/tmp/harness.bc", "/tmp/klee-last")
        assert "--max-time=300" in cmd

    def test_depth_limit_flag(self, diagnoser: SEDiagnoser) -> None:
        cmd = diagnoser._build_klee_cmd("/tmp/harness.bc", "/tmp/klee-last")
        assert "--max-depth=1000" in cmd

    def test_docker_prefix_when_use_docker(self, tmp_path: Path) -> None:
        d = SEDiagnoser(
            klee_path="klee",
            timeout=300,
            depth_limit=1000,
            output_dir=tmp_path,
            use_docker=True,
        )
        cmd = d._build_klee_cmd("/tmp/harness.bc", "/tmp/klee-last")
        assert "docker" in cmd[0]
        assert "klee/klee" in cmd


# ===========================================================================
# HarnessRefiner — feedback formatting and missed function computation
# ===========================================================================

class TestHarnessRefinerFeedback:
    """Tests for HarnessRefiner._build_compile_feedback() and _build_se_feedback()."""

    @pytest.fixture()
    def refiner(self, minimal_spec: VulnerabilitySpec, tmp_path: Path) -> HarnessRefiner:
        cd = CompileDiagnoser(
            clang_path="clang-14",
            llvm_link_path="llvm-link-14",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        se = SEDiagnoser(
            klee_path="klee",
            timeout=300,
            depth_limit=1000,
            output_dir=tmp_path,
        )
        return HarnessRefiner(r_max=15, spec=minimal_spec, compile_diagnoser=cd, se_diagnoser=se)

    def test_compile_feedback_format(self, refiner: HarnessRefiner) -> None:
        diag = CompileDiagnostic(
            error_class=CompileErrorClass.INCOMPLETE_TYPE,
            raw_error="error: incomplete type",
            suggested_fix="Add forward declaration.",
        )
        msg = refiner._build_compile_feedback(diag)
        assert msg["role"] == "user"
        assert "COMPILE ERROR" in msg["content"]
        assert "incomplete_type" in msg["content"]
        assert "Add forward declaration" in msg["content"]

    def test_compile_feedback_includes_relevant_source(self, refiner: HarnessRefiner) -> None:
        diag = CompileDiagnostic(
            error_class=CompileErrorClass.CONFLICTING_PROTO,
            raw_error="conflicting types",
            suggested_fix="Fix proto",
            relevant_source="bfd_vma bfd_get_32(const void *);",
        )
        msg = refiner._build_compile_feedback(diag)
        assert "bfd_get_32" in msg["content"]

    def test_se_feedback_not_reached(self, refiner: HarnessRefiner) -> None:
        diag = SEDiagnostic(
            outcome=SEOutcome.NOT_REACHED,
            functions_entered=["foo_process"],
            functions_missed=["bar_func"],
        )
        msg = refiner._build_se_feedback(diag)
        assert msg["role"] == "user"
        assert "NOT_REACHED" in msg["content"]
        assert "foo_process" in msg["content"]
        assert "bar_func" in msg["content"]

    def test_se_feedback_site_reached(self, refiner: HarnessRefiner) -> None:
        diag = SEDiagnostic(
            outcome=SEOutcome.SITE_REACHED,
            functions_entered=["foo_process"],
        )
        msg = refiner._build_se_feedback(diag)
        assert "SITE_REACHED" in msg["content"]
        assert "klee_assume" in msg["content"]


class TestHarnessRefinerMissedFunctions:
    """Tests that HarnessRefiner computes functions_missed from the call chain."""

    def test_missed_functions_computed_from_call_chain(
        self, minimal_spec: VulnerabilitySpec, tmp_path: Path
    ) -> None:
        cd = MagicMock(spec=CompileDiagnoser)
        cd.compile.return_value = (True, None)
        cd.get_harness_bc_path.return_value = str(tmp_path / "harness.bc")

        se = MagicMock(spec=SEDiagnoser)
        se.run.return_value = SEDiagnostic(
            outcome=SEOutcome.NOT_REACHED,
            functions_entered=["foo_process"],
            functions_missed=[],  # SEDiagnoser always returns []
        )

        refiner = HarnessRefiner(
            r_max=15,
            spec=minimal_spec,
            compile_diagnoser=cd,
            se_diagnoser=se,
        )
        harness = HarnessArtifacts(
            driver_c="int main(){return 0;}",
            slice_c="void foo_process(){}",
            compile_cmd="",
            link_cmd="",
            bitcode_path=None,
        )
        history: list[dict] = []
        call_chain = ["foo_process", "bar_func", "memcpy"]

        _, se_diag, _, _ = refiner.refine(harness, history, 12, 0, call_chain=call_chain)

        assert se_diag is not None
        assert "bar_func" in se_diag.functions_missed
        assert "memcpy" in se_diag.functions_missed
        assert "foo_process" not in se_diag.functions_missed  # was entered

    def test_no_call_chain_no_change(
        self, minimal_spec: VulnerabilitySpec, tmp_path: Path
    ) -> None:
        cd = MagicMock(spec=CompileDiagnoser)
        cd.compile.return_value = (True, None)
        cd.get_harness_bc_path.return_value = str(tmp_path / "harness.bc")

        se = MagicMock(spec=SEDiagnoser)
        se.run.return_value = SEDiagnostic(
            outcome=SEOutcome.NOT_REACHED,
            functions_entered=["foo_process"],
            functions_missed=[],
        )

        refiner = HarnessRefiner(
            r_max=15,
            spec=minimal_spec,
            compile_diagnoser=cd,
            se_diagnoser=se,
        )
        harness = HarnessArtifacts(
            driver_c="int main(){return 0;}",
            slice_c="void foo_process(){}",
            compile_cmd="",
            link_cmd="",
            bitcode_path=None,
        )
        _, se_diag, _, _ = refiner.refine(harness, [], 12, 0, call_chain=None)
        assert se_diag is not None
        assert se_diag.functions_missed == []  # unchanged when no call_chain

    def test_compile_failure_returns_none_se_diag(
        self, minimal_spec: VulnerabilitySpec, tmp_path: Path
    ) -> None:
        cd = MagicMock(spec=CompileDiagnoser)
        cd.compile.return_value = (
            False,
            CompileDiagnostic(
                error_class=CompileErrorClass.OTHER,
                raw_error="syntax error",
                suggested_fix="fix it",
            ),
        )
        se = MagicMock(spec=SEDiagnoser)

        refiner = HarnessRefiner(
            r_max=15,
            spec=minimal_spec,
            compile_diagnoser=cd,
            se_diagnoser=se,
        )
        harness = HarnessArtifacts(
            driver_c="int main(){return 0;}",
            slice_c="void foo_process(){}",
            compile_cmd="",
            link_cmd="",
            bitcode_path=None,
        )
        _, se_diag, t_out, _ = refiner.refine(harness, [], 12, 0)
        assert se_diag is None
        assert t_out == 13  # turn incremented
        se.run.assert_not_called()


# ===========================================================================
# LLMOrchestrator — configuration and turn budgets
# ===========================================================================

class TestPhase2Config:
    """Tests for Phase2Config defaults and post_init."""

    def test_default_budgets_match_paper(self, tmp_path: Path) -> None:
        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert cfg.T_explore == 8   # Paper §4: T_explore = 8
        assert cfg.T_author == 12   # Paper §4: T_author = 12
        assert cfg.T_max == 60      # Paper §4: T_max = 60
        assert cfg.R_max == 15      # Paper §4: R_max = 15
        assert cfg.klee_timeout == 300  # Paper §4: T_klee = 300s
        assert cfg.klee_depth_limit == 1000  # Paper §4: depth = 1000

    def test_model_is_claude(self, tmp_path: Path) -> None:
        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert "claude" in cfg.llm_model.lower()

    def test_paths_resolved_to_absolute(self, tmp_path: Path) -> None:
        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert cfg.project_root.is_absolute()
        assert cfg.output_dir.is_absolute()


class TestLLMOrchestratorSystemPrompt:
    """Tests for LLMOrchestrator._build_system_prompt()."""

    @pytest.fixture()
    def orchestrator(self, minimal_spec: VulnerabilitySpec, tmp_path: Path) -> LLMOrchestrator:
        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        return LLMOrchestrator(cfg, minimal_spec)

    def test_system_prompt_contains_spec(self, orchestrator: LLMOrchestrator) -> None:
        prompt = orchestrator._build_system_prompt()
        assert "foo_process" in prompt
        assert "CWE-120" in prompt
        assert "src/foo.c" in prompt

    def test_system_prompt_contains_turn_budgets(self, orchestrator: LLMOrchestrator) -> None:
        prompt = orchestrator._build_system_prompt()
        assert "0-7" in prompt or "turns 0" in prompt  # T_explore range shown

    def test_authoring_prompt_contains_sailor_sink(self, orchestrator: LLMOrchestrator) -> None:
        # SAILOR_SINK_REACHED belongs in the authoring prompt, not the system prompt
        prompt = orchestrator._build_authoring_prompt(8, ["foo_process"])
        assert "SAILOR_SINK_REACHED" in prompt

    def test_system_prompt_contains_harness_rules(self, orchestrator: LLMOrchestrator) -> None:
        prompt = orchestrator._build_system_prompt()
        assert "klee_make_symbolic" in prompt
        assert "klee_assume" in prompt


class TestLLMOrchestratorParseHarness:
    """Tests for LLMOrchestrator._parse_harness_from_response() fallback behavior."""

    @pytest.fixture()
    def orchestrator(self, minimal_spec: VulnerabilitySpec, tmp_path: Path) -> LLMOrchestrator:
        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        return LLMOrchestrator(cfg, minimal_spec)

    def test_parses_two_c_blocks(self, orchestrator: LLMOrchestrator) -> None:
        response = (
            "```c\nint main() { klee_make_symbolic(&x, 4, \"x\"); foo_process(NULL); }\n```\n"
            "```c\nvoid foo_process(void *p) { klee_warning_once(\"SPINE_PROBE:foo_process:ENTRY\"); }\n```"
        )
        harness = orchestrator._parse_harness_from_response(response, [], [], [])
        assert "main" in harness.driver_c
        assert "foo_process" in harness.slice_c

    def test_falls_back_when_no_blocks(self, orchestrator: LLMOrchestrator) -> None:
        response = "I cannot write the code right now."
        harness = orchestrator._parse_harness_from_response(response, [], [], [])
        # fallback minimal driver and slice should still reference the entrypoint
        assert "foo_process" in harness.driver_c or "foo_process" in harness.slice_c

    def test_sailor_sink_injected(self, orchestrator: LLMOrchestrator) -> None:
        response = (
            "```c\nint main() { klee_make_symbolic(&x, 4, \"x\"); foo_process(NULL); }\n```\n"
            "```c\nvoid foo_process(void *p) { klee_warning_once(\"SPINE_PROBE:foo_process:ENTRY\"); }\n```"
        )
        harness = orchestrator._parse_harness_from_response(response, [], [], [])
        assert "SAILOR_SINK_REACHED" in harness.slice_c

    def test_update_harness_replaces_code_blocks(self, orchestrator: LLMOrchestrator) -> None:
        old_harness = HarnessArtifacts(
            driver_c="old driver",
            slice_c="old slice",
            compile_cmd="",
            link_cmd="",
        )
        response = (
            "```c\nnew driver int main(){}\n```\n"
            "```c\nnew slice void foo(){}\n```"
        )
        new_harness = orchestrator._update_harness_from_response(response, old_harness)
        assert "new driver" in new_harness.driver_c
        assert "new slice" in new_harness.slice_c

    def test_update_harness_falls_back_on_empty(self, orchestrator: LLMOrchestrator) -> None:
        old_harness = HarnessArtifacts(
            driver_c="old driver",
            slice_c="old slice",
            compile_cmd="",
            link_cmd="",
        )
        new_harness = orchestrator._update_harness_from_response("no code here", old_harness)
        assert new_harness.driver_c == "old driver"
        assert new_harness.slice_c == "old slice"


# ===========================================================================
# Phase2Pipeline — no-specs smoke test
# ===========================================================================

class TestPhase2Pipeline:
    """Tests for Phase2Pipeline.run()."""

    def test_empty_specs_returns_empty(self, tmp_path: Path) -> None:
        from sailor.phase2.pipeline import Phase2Pipeline

        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        pipeline = Phase2Pipeline(cfg)
        results = pipeline.run(specs=[])
        assert results == []

    def test_empty_specs_writes_result_file(self, tmp_path: Path) -> None:
        from sailor.phase2.pipeline import Phase2Pipeline
        import json

        cfg = Phase2Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        pipeline = Phase2Pipeline(cfg)
        pipeline.run(specs=[])
        result_file = tmp_path / "out" / "phase2_results.json"
        assert result_file.exists()
        data = json.loads(result_file.read_text())
        assert data == []
