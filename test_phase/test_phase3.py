"""Unit tests for sailor/phase3/ components."""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sailor.models.schemas import (
    ASanViolationType,
    BuildContext,
    Phase2Result,
    SEOutcome,
    ValidationVerdict,
    VulnerabilitySpec,
    WitnessInput,
    WitnessValue,
)
from sailor.phase3.asan_compiler import ASanCompileError, ASanCompiler
from sailor.phase3.concrete_executor import ConcreteExecutor
from sailor.phase3.pipeline import Phase3Config, Phase3Pipeline
from sailor.phase3.replay_driver_gen import ReplayDriverGenerator
from sailor.phase3.result_classifier import ResultClassifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_spec(**kwargs) -> VulnerabilitySpec:
    defaults = dict(
        rule_id="cpp/buffer-overflow",
        file="/proj/src/foo.c",
        line=42,
        col=1,
        cwe="CWE-120",
        entrypoint="process",
        call_chain=["process", "copy_data"],
        assertion_template="n <= dst_len",
        message="Buffer overflow in process()",
        snippet="memcpy(dst, src, n);",
        build_context=BuildContext(include_paths=["/proj/include"], defines=["FOO=1"]),
    )
    defaults.update(kwargs)
    return VulnerabilitySpec(**defaults)


def _make_witness(**kwargs) -> WitnessInput:
    from sailor.models.schemas import HarnessArtifacts
    harness = HarnessArtifacts(
        driver_c='#include <klee/klee.h>\nint main() { klee_make_symbolic(&x, 4, "x"); }',
        slice_c="",
        compile_cmd="clang -emit-llvm driver.c -o driver.bc",
        link_cmd="llvm-link driver.bc slice.bc -o harness.bc",
    )
    defaults = dict(
        spec_id="cpp/buffer-overflow:/proj/src/foo.c:42",
        harness=harness,
        ktest_paths=[],
        outcome=SEOutcome.BUG_TRIGGERED,
        turns_used=3,
        refine_count=1,
    )
    defaults.update(kwargs)
    return WitnessInput(**defaults)


# ---------------------------------------------------------------------------
# TestReplayDriverGeneratorKleeRemoval
# ---------------------------------------------------------------------------

class TestReplayDriverGeneratorKleeRemoval:
    """_remove_klee_* strip the right calls without touching other code."""

    def setup_method(self):
        witness = _make_witness()
        self.gen = ReplayDriverGenerator(
            witness=witness,
            output_dir=Path("/tmp"),
        )

    def test_remove_klee_assume_single(self):
        src = 'klee_assume(x > 0);\nfoo();\n'
        result = self.gen._remove_klee_assume(src)
        assert "klee_assume" not in result
        assert "foo();" in result

    def test_remove_klee_assume_multiline(self):
        src = 'klee_assume(\n  x > 0\n);\nfoo();\n'
        result = self.gen._remove_klee_assume(src)
        assert "klee_assume" not in result

    def test_remove_klee_assert(self):
        src = 'klee_assert(buf != NULL);\nreturn 0;\n'
        result = self.gen._remove_klee_assert(src)
        assert "klee_assert" not in result
        assert "return 0;" in result

    def test_remove_klee_warning_once(self):
        src = 'klee_warning_once("SPINE_PROBE:foo:ENTRY");\nbar();\n'
        result = self.gen._remove_klee_warning(src)
        assert "klee_warning_once" not in result
        assert "bar();" in result

    def test_remove_preserves_regular_assignments(self):
        # Regular assignments must NOT be removed.
        src = 'ndo->ndo_vflag = 3;\nklee_assume(x > 0);\nprocess(ndo);\n'
        result = self.gen._remove_klee_assume(src)
        assert "ndo->ndo_vflag = 3;" in result
        assert "process(ndo);" in result

    def test_remove_all_klee_calls_combined(self):
        src = (
            'klee_warning_once("SPINE_PROBE:f:ENTRY");\n'
            'klee_assume(n < 100);\n'
            'klee_assert(p != NULL);\n'
            'actual_work();\n'
        )
        result = self.gen._remove_klee_assume(src)
        result = self.gen._remove_klee_assert(result)
        result = self.gen._remove_klee_warning(result)
        assert "klee_" not in result
        assert "actual_work();" in result


# ---------------------------------------------------------------------------
# TestReplayDriverGeneratorKleeInclude
# ---------------------------------------------------------------------------

class TestReplayDriverGeneratorKleeInclude:
    def setup_method(self):
        self.gen = ReplayDriverGenerator(witness=_make_witness(), output_dir=Path("/tmp"))

    def test_removes_klee_include(self):
        src = '#include <klee/klee.h>\n#include <stdio.h>\nint main() {}\n'
        result = self.gen._add_ktest_include(src)
        assert '<klee/klee.h>' not in result

    def test_injects_string_and_stdlib(self):
        src = '#include <klee/klee.h>\nint main() {}\n'
        result = self.gen._add_ktest_include(src)
        assert '#include <string.h>' in result
        assert '#include <stdlib.h>' in result

    def test_no_klee_include_still_injects(self):
        src = 'int main() { return 0; }\n'
        result = self.gen._add_ktest_include(src)
        assert '#include <string.h>' in result


# ---------------------------------------------------------------------------
# TestReplayDriverGeneratorReplaceSymbolic
# ---------------------------------------------------------------------------

class TestReplayDriverGeneratorReplaceSymbolic:
    def setup_method(self):
        self.gen = ReplayDriverGenerator(witness=_make_witness(), output_dir=Path("/tmp"))

    def test_replaces_known_symbolic_variable(self):
        src = 'klee_make_symbolic(&buf, 4, "buf");'
        values = [WitnessValue(name="buf", size_bytes=4, data_hex="deadbeef", data_interpreted=0xDEADBEEF)]
        result = self.gen._replace_klee_make_symbolic(src, values)
        assert "memcpy" in result
        assert "klee_make_symbolic" not in result

    def test_unknown_variable_becomes_comment(self):
        src = 'klee_make_symbolic(&x, 4, "x");'
        result = self.gen._replace_klee_make_symbolic(src, [])
        assert "/* klee_make_symbolic" in result
        assert "no witness value" in result

    def test_hex_bytes_appear_in_memcpy(self):
        src = 'klee_make_symbolic(&v, 2, "v");'
        values = [WitnessValue(name="v", size_bytes=2, data_hex="cafe", data_interpreted=0xCAFE)]
        result = self.gen._replace_klee_make_symbolic(src, values)
        assert "\\xca\\xfe" in result


# ---------------------------------------------------------------------------
# TestReplayDriverGeneratorPreamble
# ---------------------------------------------------------------------------

class TestReplayDriverGeneratorPreamble:
    def test_prepends_preamble(self):
        gen = ReplayDriverGenerator(
            witness=_make_witness(),
            output_dir=Path("/tmp"),
            project_preamble="#include <net/if.h>",
        )
        result = gen._inject_project_preamble("int main() {}")
        assert result.startswith("#include <net/if.h>")

    def test_strips_conflicting_struct(self):
        gen = ReplayDriverGenerator(
            witness=_make_witness(),
            output_dir=Path("/tmp"),
            project_preamble="#include <net/if.h>",
            project_struct_names=["netdissect_options"],
        )
        src = (
            "typedef struct netdissect_options {\n"
            "  int vflag;\n"
            "} netdissect_options;\n"
            "int main() {}"
        )
        result = gen._inject_project_preamble(src)
        assert "typedef struct netdissect_options" not in result
        assert "int main()" in result


# ---------------------------------------------------------------------------
# TestASanCompilerDockerDelegation
# ---------------------------------------------------------------------------

class TestASanCompilerDockerDelegation:
    def test_compile_project_delegates_to_runner(self, tmp_path):
        runner = MagicMock()
        runner.build_asan_archive.return_value = str(tmp_path / "project_asan.a")

        compiler = ASanCompiler(
            clang_path="clang",
            project_root=tmp_path,
            build_context=BuildContext(),
            output_dir=tmp_path,
            build_command="make",
            docker_runner=runner,
        )
        result = compiler.compile_project()
        runner.build_asan_archive.assert_called_once_with(
            project_dir=str(tmp_path),
            build_command="make",
        )
        assert isinstance(result, Path)

    def test_compile_replay_driver_returns_sentinel_in_docker_mode(self, tmp_path):
        runner = MagicMock()
        compiler = ASanCompiler(
            clang_path="clang",
            project_root=tmp_path,
            build_context=BuildContext(),
            output_dir=tmp_path,
            docker_runner=runner,
        )
        # Should not raise; returns sentinel path without calling runner
        sentinel = compiler.compile_replay_driver(
            tmp_path / "replay_driver.c",
            tmp_path / "project_asan.a",
        )
        assert sentinel == tmp_path / "reproducer"
        runner.run_asan_replay.assert_not_called()

    def test_compile_project_local_raises_on_no_sources(self, tmp_path):
        compiler = ASanCompiler(
            clang_path="clang",
            project_root=tmp_path,
            build_context=BuildContext(),
            output_dir=tmp_path,
        )
        with pytest.raises(ASanCompileError, match="No compilable source files"):
            compiler.compile_project()


# ---------------------------------------------------------------------------
# TestASanCompilerSourceDiscovery
# ---------------------------------------------------------------------------

class TestASanCompilerSourceDiscovery:
    def test_excludes_test_directories(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "src" / "foo.c").write_text("int f() {}")
        (tmp_path / "tests" / "bar.c").write_text("int test() {}")

        compiler = ASanCompiler(
            clang_path="clang",
            project_root=tmp_path,
            build_context=BuildContext(),
            output_dir=tmp_path,
        )
        sources = compiler._sources_from_filesystem()
        names = [p.name for p in sources]
        assert "foo.c" in names
        assert "bar.c" not in names

    def test_excludes_fuzz_directories(self, tmp_path):
        (tmp_path / "fuzz").mkdir()
        (tmp_path / "fuzz" / "fuzz_target.c").write_text("int main() {}")
        (tmp_path / "main.c").write_text("int main() {}")

        compiler = ASanCompiler(
            clang_path="clang",
            project_root=tmp_path,
            build_context=BuildContext(),
            output_dir=tmp_path,
        )
        sources = compiler._sources_from_filesystem()
        names = [p.name for p in sources]
        assert "main.c" in names
        assert "fuzz_target.c" not in names


# ---------------------------------------------------------------------------
# TestConcreteExecutorDockerDelegation
# ---------------------------------------------------------------------------

class TestConcreteExecutorDockerDelegation:
    def test_execute_delegates_to_runner(self, tmp_path):
        runner = MagicMock()
        runner.run_asan_replay.return_value = {
            "crashed": True,
            "asan_output": "ERROR: AddressSanitizer: heap-buffer-overflow",
        }
        replay_driver = tmp_path / "replay_driver.c"
        replay_driver.write_text("int main() {}")
        archive = tmp_path / "project_asan.a"

        executor = ConcreteExecutor(
            timeout=30,
            output_dir=tmp_path,
            docker_runner=runner,
        )
        crashed, output = executor.execute(
            tmp_path / "reproducer",
            replay_driver_path=replay_driver,
            project_archive=archive,
            include_paths=["/proj/include"],
        )
        assert crashed is True
        assert "heap-buffer-overflow" in output
        runner.run_asan_replay.assert_called_once()
        call_kwargs = runner.run_asan_replay.call_args.kwargs
        assert "int main() {}" in call_kwargs["replay_driver_c"]
        assert call_kwargs["include_paths"] == ["/proj/include"]

    def test_execute_writes_asan_output_in_docker_mode(self, tmp_path):
        runner = MagicMock()
        runner.run_asan_replay.return_value = {"crashed": False, "asan_output": "clean run"}
        replay_driver = tmp_path / "replay_driver.c"
        replay_driver.write_text("")
        archive = tmp_path / "project_asan.a"

        executor = ConcreteExecutor(output_dir=tmp_path, docker_runner=runner)
        executor.execute(
            tmp_path / "reproducer",
            replay_driver_path=replay_driver,
            project_archive=archive,
        )
        assert (tmp_path / "asan_output.txt").read_text() == "clean run"

    def test_execute_raises_in_docker_mode_without_replay_driver(self, tmp_path):
        runner = MagicMock()
        executor = ConcreteExecutor(docker_runner=runner)
        with pytest.raises(ValueError, match="replay_driver_path"):
            executor.execute(tmp_path / "reproducer")

    def test_detect_crash_nonzero_exit(self):
        executor = ConcreteExecutor()
        assert executor._detect_crash("", "", 1) is True

    def test_detect_crash_zero_exit_clean(self):
        executor = ConcreteExecutor()
        assert executor._detect_crash("", "", 0) is False

    def test_detect_crash_asan_error_in_stderr(self):
        executor = ConcreteExecutor()
        assert executor._detect_crash("", "ERROR: AddressSanitizer: heap-buffer-overflow", 0) is True

    def test_detect_crash_summary_line(self):
        executor = ConcreteExecutor()
        assert executor._detect_crash("", "SUMMARY: AddressSanitizer: heap-buffer-overflow", 0) is True


# ---------------------------------------------------------------------------
# TestResultClassifierCWERefinement
# ---------------------------------------------------------------------------

class TestResultClassifierCWERefinement:
    def setup_method(self):
        self.clf = ResultClassifier(project_root=Path("/proj"))

    def test_cwe120_heap_overflow_becomes_cwe122(self):
        refined = self.clf._refine_cwe("CWE-120", ASanViolationType.HEAP_BUFFER_OVERFLOW)
        assert refined == "CWE-122"

    def test_cwe120_stack_overflow_becomes_cwe121(self):
        refined = self.clf._refine_cwe("CWE-120", ASanViolationType.STACK_BUFFER_OVERFLOW)
        assert refined == "CWE-121"

    def test_cwe120_other_type_unchanged(self):
        refined = self.clf._refine_cwe("CWE-120", ASanViolationType.USE_AFTER_FREE)
        assert refined == "CWE-120"

    def test_non_cwe120_unchanged(self):
        refined = self.clf._refine_cwe("CWE-416", ASanViolationType.USE_AFTER_FREE)
        assert refined == "CWE-416"

    def test_cwe_case_insensitive(self):
        refined = self.clf._refine_cwe("cwe-120", ASanViolationType.HEAP_BUFFER_OVERFLOW)
        assert refined == "CWE-122"


# ---------------------------------------------------------------------------
# TestResultClassifierIsProjectSource
# ---------------------------------------------------------------------------

class TestResultClassifierIsProjectSource:
    def setup_method(self, tmp_path=None):
        self._tmp = Path(tempfile.mkdtemp())
        self.clf = ResultClassifier(project_root=self._tmp)

    def test_empty_path_returns_false(self):
        assert self.clf._is_project_source("") is False

    def test_harness_file_returns_false(self):
        assert self.clf._is_project_source("driver.c") is False
        assert self.clf._is_project_source("replay_driver.c") is False
        assert self.clf._is_project_source("stubs.c") is False

    def test_system_path_returns_false(self):
        assert self.clf._is_project_source("/usr/include/stdio.h") is False
        assert self.clf._is_project_source("/lib/x86_64-linux-gnu/libc.so.6") is False

    def test_project_source_returns_true(self):
        src = self._tmp / "src" / "foo.c"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.touch()
        assert self.clf._is_project_source(str(src)) is True

    def test_nonexistent_path_outside_project_returns_false(self):
        assert self.clf._is_project_source("/some/other/path/bar.c") is False


# ---------------------------------------------------------------------------
# TestResultClassifierClassify
# ---------------------------------------------------------------------------

class TestResultClassifierClassify:
    def setup_method(self, tmp_path=None):
        self._tmp = Path(tempfile.mkdtemp())
        self.clf = ResultClassifier(project_root=self._tmp)
        self.spec = _make_spec(file=str(self._tmp / "src/foo.c"))

    def test_no_crash_is_false_positive(self):
        result = self.clf.classify(
            crashed=False, asan_output="", spec=self.spec, witness_values=[]
        )
        assert result.verdict == ValidationVerdict.FALSE_POSITIVE

    def test_crash_without_asan_error_is_false_positive(self):
        result = self.clf.classify(
            crashed=True,
            asan_output="Segmentation fault (core dumped)",
            spec=self.spec,
            witness_values=[],
        )
        assert result.verdict == ValidationVerdict.FALSE_POSITIVE

    def test_crash_in_harness_file_is_false_positive(self):
        asan_output = (
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234\n"
            "#0 0x400abc in main driver.c:10\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow driver.c:10 in main\n"
        )
        result = self.clf.classify(
            crashed=True,
            asan_output=asan_output,
            spec=self.spec,
            witness_values=[],
        )
        assert result.verdict == ValidationVerdict.FALSE_POSITIVE

    def test_crash_in_project_source_is_confirmed(self, tmp_path=None):
        src = self._tmp / "src" / "foo.c"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.touch()

        asan_output = (
            f"ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234\n"
            f"#0 0x400abc in copy_data {str(src)}:55\n"
            f"SUMMARY: AddressSanitizer: heap-buffer-overflow {str(src)}:55 in copy_data\n"
        )
        result = self.clf.classify(
            crashed=True,
            asan_output=asan_output,
            spec=self.spec,
            witness_values=[],
        )
        assert result.verdict == ValidationVerdict.CONFIRMED

    def test_confirmed_result_refines_cwe120(self, tmp_path=None):
        src = self._tmp / "src" / "bar.c"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.touch()
        spec = _make_spec(cwe="CWE-120", file=str(self._tmp / "src/bar.c"))

        asan_output = (
            f"ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234\n"
            f"#0 0x400abc in vuln_func {str(src)}:10\n"
            f"SUMMARY: AddressSanitizer: heap-buffer-overflow {str(src)}:10 in vuln_func\n"
        )
        result = self.clf.classify(
            crashed=True, asan_output=asan_output, spec=spec, witness_values=[]
        )
        assert result.verdict == ValidationVerdict.CONFIRMED
        assert result.cwe == "CWE-122"


# ---------------------------------------------------------------------------
# TestPhase3Config
# ---------------------------------------------------------------------------

class TestPhase3Config:
    def test_default_clang_path(self, tmp_path):
        cfg = Phase3Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert cfg.clang_path == "clang"

    def test_docker_runner_default_none(self, tmp_path):
        cfg = Phase3Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert cfg.docker_runner is None

    def test_build_command_field_exists(self, tmp_path):
        cfg = Phase3Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
            build_command="make all",
        )
        assert cfg.build_command == "make all"

    def test_replay_driver_preamble_default_empty(self, tmp_path):
        cfg = Phase3Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        assert cfg.replay_driver_preamble == ""
        assert cfg.replay_driver_struct_names == []


# ---------------------------------------------------------------------------
# TestPhase3PipelineNoQualifying
# ---------------------------------------------------------------------------

class TestPhase3PipelineNoQualifying:
    def test_empty_phase2_results_returns_zero_counts(self, tmp_path):
        cfg = Phase3Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        pipeline = Phase3Pipeline(cfg)
        result = pipeline.run(phase2_results=[], specs=[])
        assert result.total_processed == 0
        assert result.confirmed == 0
        assert result.false_positives == 0
        assert result.errors == 0

    def test_non_bug_triggered_results_are_skipped(self, tmp_path):
        cfg = Phase3Config(
            project_name="test",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        pipeline = Phase3Pipeline(cfg)
        spec = _make_spec()
        p2r = Phase2Result(
            spec_id="cpp/buffer-overflow:/proj/src/foo.c:42",
            outcome=SEOutcome.NOT_REACHED,
            turns_used=5,
            timestamp="2024-01-01T00:00:00Z",
        )
        result = pipeline.run(phase2_results=[p2r], specs=[spec])
        assert result.total_processed == 0

    def test_output_files_written_for_empty_run(self, tmp_path):
        cfg = Phase3Config(
            project_name="proj",
            project_root=tmp_path,
            output_dir=tmp_path / "out",
        )
        pipeline = Phase3Pipeline(cfg)
        pipeline.run(phase2_results=[], specs=[])
        assert (tmp_path / "out" / "phase3_results.json").exists()
        assert (tmp_path / "out" / "phase3_summary.json").exists()
