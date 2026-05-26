"""File validation service — stateless structural checks for uploaded files."""

import json
import re

from shared.contracts.sailor_models import FileValidationResult, FileValidationSeverity, Issue


def _ok(message: str, detected_format: str, issues: list | None = None) -> FileValidationResult:
    return FileValidationResult(valid=True, severity=FileValidationSeverity.info, message=message, detected_format=detected_format, issues=issues)


def _err(message: str, detected_format: str, issues: list | None = None) -> FileValidationResult:
    return FileValidationResult(valid=False, severity=FileValidationSeverity.error, message=message, detected_format=detected_format, issues=issues)


def _warn(message: str, detected_format: str, issues: list | None = None) -> FileValidationResult:
    return FileValidationResult(valid=True, severity=FileValidationSeverity.warning, message=message, detected_format=detected_format, issues=issues)


class ValidatorService:
    def validate(self, filename: str, content_bytes: bytes) -> FileValidationResult:
        name_lower = filename.lower()

        if name_lower.endswith(".sarif") or (name_lower.endswith(".json") and self._looks_like_sarif(content_bytes)):
            return self._validate_sarif(content_bytes)
        if name_lower == "findings.json":
            return self._validate_findings(content_bytes)
        if name_lower == "fact_packs.json":
            return self._validate_fact_packs(content_bytes)
        if name_lower in ("specifications.json", "spec.json"):
            return self._validate_spec(content_bytes)
        if name_lower.endswith(".c"):
            return self._validate_c_source(content_bytes, filename)
        if name_lower.endswith(".ql"):
            return self._validate_ql(content_bytes)
        if name_lower.endswith(".ktest"):
            return self._validate_ktest(content_bytes)
        if name_lower.endswith(".bc"):
            return self._validate_bitcode(content_bytes)

        return _ok("File accepted (no structural validation for this type).", "unknown")

    def _looks_like_sarif(self, content: bytes) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "runs" in data
        except Exception:
            return False

    def _validate_sarif(self, content: bytes) -> FileValidationResult:
        detected_format = self._sniff_format(content)
        if detected_format != "json":
            return _err(
                f"Expected SARIF structure but got {detected_format}.",
                detected_format,
                [Issue(severity=FileValidationSeverity.error, message=f"File type mismatch: expected JSON/SARIF, got {detected_format}", rule="sarif.type_mismatch")],
            )
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return _err(
                f"Not valid JSON: {exc}",
                "invalid_json",
                [Issue(severity=FileValidationSeverity.error, message=str(exc), rule="sarif.invalid_json")],
            )
        if "runs" not in data:
            return _err(
                'Missing "runs" array — not a valid SARIF 2.1.0 file.',
                "json",
                [Issue(severity=FileValidationSeverity.error, message='Missing "runs" array', rule="sarif.missing_runs")],
            )
        total = sum(len(r.get("results", [])) for r in data.get("runs", []))
        if total == 0:
            return _warn(
                "SARIF is valid but contains 0 results.",
                "sarif",
                [Issue(severity=FileValidationSeverity.warning, message="0 results in SARIF", rule="sarif.empty_results")],
            )
        return _ok(f"Valid SARIF with {total} result(s).", "sarif")

    def _validate_findings(self, content: bytes) -> FileValidationResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return _err(f"Not valid JSON: {exc}", "invalid_json", [Issue(severity=FileValidationSeverity.error, message=str(exc))])
        if not isinstance(data, list):
            return _err("findings.json must be a JSON array.", "json", [Issue(severity=FileValidationSeverity.error, message="Expected JSON array")])
        issues = []
        required = {"finding_id", "rule_id", "cwe"}
        for i, item in enumerate(data):
            missing = required - set(item.keys())
            if missing:
                issues.append(Issue(severity=FileValidationSeverity.error, message=f"Entry {i} missing required fields: {sorted(missing)}", line=None))
        if issues:
            return _err(f"findings.json has {len(issues)} validation error(s).", "findings_json", issues)
        return _ok(f"Valid findings.json with {len(data)} entries.", "findings_json")

    def _validate_fact_packs(self, content: bytes) -> FileValidationResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return _err(f"Not valid JSON: {exc}", "invalid_json", [Issue(severity=FileValidationSeverity.error, message=str(exc))])
        if not isinstance(data, list):
            return _err("fact_packs.json must be a JSON array.", "json", [Issue(severity=FileValidationSeverity.error, message="Expected JSON array")])
        issues = []
        for i, item in enumerate(data):
            if "finding" not in item:
                issues.append(Issue(severity=FileValidationSeverity.error, message=f"Entry {i} missing 'finding' field."))
            if "build_context" not in item:
                issues.append(Issue(severity=FileValidationSeverity.error, message=f"Entry {i} missing 'build_context' field."))
        if issues:
            return _err(f"fact_packs.json has {len(issues)} error(s).", "fact_packs_json", issues)
        return _ok(f"Valid fact_packs.json with {len(data)} entries.", "fact_packs_json")

    def _validate_spec(self, content: bytes) -> FileValidationResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return _err(f"Not valid JSON: {exc}", "invalid_json", [Issue(severity=FileValidationSeverity.error, message=str(exc))])
        specs = data if isinstance(data, list) else [data]
        issues = []
        for i, s in enumerate(specs):
            if not s.get("assertion_template"):
                issues.append(Issue(severity=FileValidationSeverity.error, message=f"Spec[{i}]: assertion_template must be non-empty."))
            if not s.get("entrypoint"):
                issues.append(Issue(severity=FileValidationSeverity.error, message=f"Spec[{i}]: entrypoint must be non-empty."))
        if issues:
            return _err(f"Spec JSON has {len(issues)} error(s).", "spec_json", issues)
        return _ok(f"Valid spec JSON ({len(specs)} spec(s)).", "spec_json")

    def _validate_c_source(self, content: bytes, filename: str) -> FileValidationResult:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return _err("File is not valid UTF-8 text.", "binary", [Issue(severity=FileValidationSeverity.error, message="Not valid UTF-8")])

        # replay_driver.c: check for klee_* call sites (rule: replay_driver.klee_call_present)
        if filename.lower() == "replay_driver.c":
            klee_calls = re.findall(r'\bklee_\w+\s*\(', text)
            if klee_calls:
                issues = [Issue(
                    severity=FileValidationSeverity.error,
                    message=f"replay_driver.c must not contain klee_* calls (found: {', '.join(set(c.rstrip('(').strip() for c in klee_calls))})",
                    rule="replay_driver.klee_call_present",
                )]
                return _err("replay_driver.c contains klee_* call sites — these must be removed.", "c_source", issues)

        return _ok("C source file accepted (syntax check requires container).", "c_source")

    def _validate_ql(self, content: bytes) -> FileValidationResult:
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return _err("File is not valid UTF-8 text.", "binary", [Issue(severity=FileValidationSeverity.error, message="Not valid UTF-8")])
        return _ok("QL file accepted (compile check requires container).", "ql_source")

    def _validate_ktest(self, content: bytes) -> FileValidationResult:
        if len(content) < 5 or content[:5] != b"KTEST":
            return _err(
                'File does not start with "KTEST" magic bytes — not a valid .ktest file.',
                "unknown",
                [Issue(severity=FileValidationSeverity.error, message="Missing KTEST magic bytes", rule="ktest.bad_magic")],
            )
        return _ok("Valid .ktest file.", "ktest")

    def _validate_bitcode(self, content: bytes) -> FileValidationResult:
        if len(content) < 2 or content[:2] != b"BC":
            return _err(
                'File does not start with "BC" magic bytes (0x42 0x43) — not valid LLVM bitcode.',
                "unknown",
                [Issue(severity=FileValidationSeverity.error, message="Missing BC magic bytes", rule="bitcode.bad_magic")],
            )
        return _ok("Valid LLVM bitcode file.", "llvm_bitcode")

    def _sniff_format(self, content: bytes) -> str:
        if content[:4] == b"%PDF":
            return "pdf"
        if content[:4] == b"\x7fELF":
            return "elf"
        if content[:2] == b"PK":
            return "zip"
        try:
            content.decode("utf-8")
            return "json"
        except UnicodeDecodeError:
            return "binary"


_validator_service = ValidatorService()


def get_validator_service() -> ValidatorService:
    return _validator_service
