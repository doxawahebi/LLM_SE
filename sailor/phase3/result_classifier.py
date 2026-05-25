"""Phase 3 — Result Classifier.

Parses ASan output and classifies each concrete execution as CONFIRMED,
FALSE_POSITIVE, or ERROR.  Also builds the verified_bug.json payload.
"""

from __future__ import annotations

import datetime
import logging
import re
from pathlib import Path

from sailor.models.schemas import (
    ASanReport,
    ASanViolationType,
    ValidationResult,
    ValidationVerdict,
    VulnerabilitySpec,
    WitnessValue,
)

logger = logging.getLogger("sailor.phase3.result_classifier")

# Maps the raw ASan error type substring to the enum value.
_ASAN_TYPE_MAP: dict[str, ASanViolationType] = {
    "heap-buffer-overflow": ASanViolationType.HEAP_BUFFER_OVERFLOW,
    "global-buffer-overflow": ASanViolationType.HEAP_BUFFER_OVERFLOW,
    "stack-buffer-overflow": ASanViolationType.STACK_BUFFER_OVERFLOW,
    "heap-use-after-free": ASanViolationType.USE_AFTER_FREE,
    "null-dereference": ASanViolationType.NULL_DEREFERENCE,
}

# "ERROR: AddressSanitizer: heap-buffer-overflow on address …"
_ASAN_ERROR_PAT = re.compile(
    r"ERROR:\s*AddressSanitizer:\s*([\w-]+)", re.IGNORECASE
)

# Stack frame: "    #N 0xADDR in <func> <file>:<line>[:<col>]"
_STACK_FRAME_PAT = re.compile(
    r"#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)\s+([^\s:]+):(\d+)",
    re.IGNORECASE,
)

# Files that belong to the harness, not the project source.
_HARNESS_FILES = frozenset(["driver.c", "stubs.c", "replay_driver.c"])

# System path prefixes that are never part of the project source.
_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/proc/")


def _now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class ResultClassifier:
    """Parse ASan output and classify the Phase 3 execution result.

    Args:
        project_root: Root directory of the unmodified project source.
    """

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()

    def classify(
        self,
        crashed: bool,
        asan_output: str,
        spec: VulnerabilitySpec,
        witness_values: list[WitnessValue],
    ) -> ValidationResult:
        """Classify the concrete execution result.

        A CONFIRMED verdict requires all of:
        1. ``crashed`` is True.
        2. ``"ERROR: AddressSanitizer"`` appears in *asan_output*.
        3. The ASan stack trace contains at least one frame whose source file
           is inside *project_root* (not a harness or system file).

        FALSE_POSITIVE is assigned when the binary did not crash, or when the
        only crash frames are in harness files (driver.c, stubs.c,
        replay_driver.c).

        Args:
            crashed: Whether the reproducer exited abnormally.
            asan_output: Combined stdout+stderr from the execution.
            spec: The originating :class:`VulnerabilitySpec`.
            witness_values: Concrete inputs extracted from the .ktest file.

        Returns:
            A :class:`ValidationResult` with paths left as empty strings
            (the pipeline fills them in after writing output files).
        """
        asan_report = self._parse_asan_report(asan_output) if crashed else None

        if (
            crashed
            and asan_report is not None
            and "ERROR: AddressSanitizer" in asan_output
            and asan_report.is_in_project_source
        ):
            verdict = ValidationVerdict.CONFIRMED
            cwe = self._refine_cwe(spec.cwe, asan_report.violation_type)
            result_file = asan_report.file
            result_line = asan_report.line
            result_func = asan_report.func
        else:
            verdict = ValidationVerdict.FALSE_POSITIVE
            cwe = spec.cwe
            result_file = spec.file
            result_line = spec.line
            result_func = spec.entrypoint

        return ValidationResult(
            spec_id=f"{spec.rule_id}:{spec.file}:{spec.line}",
            verdict=verdict,
            cwe=cwe,
            file=result_file,
            line=result_line,
            func=result_func,
            asan_type=asan_report.violation_type if asan_report else None,
            asan_report=asan_report,
            inputs=witness_values,
            replay_driver_path="",
            asan_report_path="",
            verdict_path="",
            timestamp=_now(),
        )

    def _parse_asan_report(self, asan_output: str) -> ASanReport | None:
        """Parse ASan stderr output into a structured :class:`ASanReport`.

        Extracts the violation type from the ``ERROR: AddressSanitizer: <type>``
        line, and the first frame inside project source for file/line/func.

        Args:
            asan_output: Combined program output containing ASan diagnostics.

        Returns:
            Populated :class:`ASanReport`, or ``None`` if parsing fails.
        """
        type_match = _ASAN_ERROR_PAT.search(asan_output)
        if type_match is None:
            return None

        raw_type = type_match.group(1).lower()
        violation_type = _ASAN_TYPE_MAP.get(raw_type, ASanViolationType.UNKNOWN)

        stack_start = asan_output.find("ERROR: AddressSanitizer")
        stack_end_match = re.search(r"SUMMARY:", asan_output[stack_start:])
        if stack_end_match:
            stack_trace = asan_output[
                stack_start : stack_start + stack_end_match.start()
            ]
        else:
            stack_trace = asan_output[stack_start:]

        file_path = ""
        line_no = 0
        func_name = ""
        is_in_project = False

        for frame in _STACK_FRAME_PAT.finditer(stack_trace):
            f_func = frame.group(1)
            f_file = frame.group(2)
            f_line = int(frame.group(3))
            if self._is_project_source(f_file):
                file_path = f_file
                line_no = f_line
                func_name = f_func
                is_in_project = True
                break

        if not file_path:
            first_frame = _STACK_FRAME_PAT.search(stack_trace)
            if first_frame:
                func_name = first_frame.group(1)
                file_path = first_frame.group(2)
                line_no = int(first_frame.group(3))

        return ASanReport(
            violation_type=violation_type,
            file=file_path,
            line=line_no,
            func=func_name,
            stack_trace=stack_trace.strip(),
            is_in_project_source=is_in_project,
        )

    def _is_project_source(self, file_path: str) -> bool:
        """Return True if *file_path* points to unmodified project source.

        Excludes harness files (driver.c, stubs.c, replay_driver.c) and
        system files (paths under /usr/, /lib/, etc.).

        Args:
            file_path: Raw file path string from an ASan stack frame.

        Returns:
            True if the file is inside *project_root*.
        """
        if not file_path:
            return False

        base = Path(file_path).name
        if base in _HARNESS_FILES:
            return False

        if any(file_path.startswith(prefix) for prefix in _SYSTEM_PREFIXES):
            return False

        try:
            resolved = Path(file_path).resolve()
            return resolved.is_relative_to(self.project_root)
        except (ValueError, OSError):
            return False

    def _refine_cwe(self, cwe: str, violation: ASanViolationType) -> str:
        """Refine a coarse Phase 1 CWE using the concrete ASan evidence.

        CWE-120 (buffer copy without bounds check) is refined to:
        - CWE-122 for heap-buffer-overflow
        - CWE-121 for stack-buffer-overflow

        Args:
            cwe: Original CWE from :class:`VulnerabilitySpec`.
            violation: ASan violation category.

        Returns:
            Refined CWE string.
        """
        if cwe.upper() == "CWE-120":
            if violation == ASanViolationType.HEAP_BUFFER_OVERFLOW:
                return "CWE-122"
            if violation == ASanViolationType.STACK_BUFFER_OVERFLOW:
                return "CWE-121"
        return cwe

    def build_verified_bug_json(
        self,
        result: ValidationResult,
        spec: VulnerabilitySpec,
    ) -> dict:  # type: ignore[type-arg]
        """Build the ``verified_bug.json`` payload for a CONFIRMED result.

        Args:
            result: The CONFIRMED :class:`ValidationResult`.
            spec: The originating :class:`VulnerabilitySpec`.

        Returns:
            Dictionary matching the ``verified_bug.json`` schema.
        """
        inputs_simple = [
            {wv.name: wv.data_interpreted} for wv in result.inputs
        ]
        return {
            "verdict": result.verdict.value,
            "cwe": result.cwe,
            "file": result.file,
            "line": result.line,
            "func": result.func,
            "asan_type": result.asan_type.value if result.asan_type else None,
            "inputs": inputs_simple,
        }
