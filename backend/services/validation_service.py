"""File validation service — stateless structural checks for uploaded files."""

import json
from dataclasses import dataclass


@dataclass
class ValidationResult:
    valid: bool
    severity: str  # "error" | "warning" | "info"
    message: str
    detected_format: str


class ValidatorService:
    def validate(self, filename: str, content_bytes: bytes) -> ValidationResult:
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
            return self._validate_c_source(content_bytes)
        if name_lower.endswith(".ql"):
            return self._validate_ql(content_bytes)
        if name_lower.endswith(".ktest"):
            return self._validate_ktest(content_bytes)
        if name_lower.endswith(".bc"):
            return self._validate_bitcode(content_bytes)

        return ValidationResult(
            valid=True,
            severity="info",
            message="File accepted (no structural validation for this type).",
            detected_format="unknown",
        )

    def _looks_like_sarif(self, content: bytes) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and "runs" in data
        except Exception:
            return False

    def _validate_sarif(self, content: bytes) -> ValidationResult:
        detected_format = self._sniff_format(content)
        if detected_format != "json":
            return ValidationResult(
                valid=False,
                severity="error",
                message=f"Expected SARIF structure but got {detected_format}. Proceeding may cause parser errors.",
                detected_format=detected_format,
            )
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return ValidationResult(
                valid=False,
                severity="error",
                message=f"Not valid JSON: {exc}",
                detected_format="invalid_json",
            )
        if "runs" not in data:
            return ValidationResult(
                valid=False,
                severity="error",
                message='Missing "runs" array — not a valid SARIF 2.1.0 file.',
                detected_format="json",
            )
        total = sum(len(r.get("results", [])) for r in data.get("runs", []))
        if total == 0:
            return ValidationResult(
                valid=True,
                severity="warning",
                message="SARIF is valid but contains 0 results.",
                detected_format="sarif",
            )
        return ValidationResult(
            valid=True,
            severity="info",
            message=f"Valid SARIF with {total} result(s).",
            detected_format="sarif",
        )

    def _validate_findings(self, content: bytes) -> ValidationResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return ValidationResult(False, "error", f"Not valid JSON: {exc}", "invalid_json")
        if not isinstance(data, list):
            return ValidationResult(False, "error", "findings.json must be a JSON array.", "json")
        required = {"finding_id", "rule_id", "cwe"}
        for i, item in enumerate(data):
            missing = required - set(item.keys())
            if missing:
                return ValidationResult(
                    False, "error",
                    f"Entry {i} missing required fields: {missing}",
                    "findings_json",
                )
        return ValidationResult(True, "info", f"Valid findings.json with {len(data)} entries.", "findings_json")

    def _validate_fact_packs(self, content: bytes) -> ValidationResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return ValidationResult(False, "error", f"Not valid JSON: {exc}", "invalid_json")
        if not isinstance(data, list):
            return ValidationResult(False, "error", "fact_packs.json must be a JSON array.", "json")
        for i, item in enumerate(data):
            if "finding" not in item:
                return ValidationResult(False, "error", f"Entry {i} missing 'finding' field.", "fact_packs_json")
            if "build_context" not in item:
                return ValidationResult(False, "error", f"Entry {i} missing 'build_context' field.", "fact_packs_json")
        return ValidationResult(True, "info", f"Valid fact_packs.json with {len(data)} entries.", "fact_packs_json")

    def _validate_spec(self, content: bytes) -> ValidationResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            return ValidationResult(False, "error", f"Not valid JSON: {exc}", "invalid_json")
        # Accept array (specifications.json) or single object (spec.json)
        specs = data if isinstance(data, list) else [data]
        for i, s in enumerate(specs):
            if not s.get("assertion_template"):
                return ValidationResult(
                    False, "error",
                    f"Spec[{i}]: assertion_template must be non-empty.",
                    "spec_json",
                )
            if not s.get("entrypoint"):
                return ValidationResult(
                    False, "error",
                    f"Spec[{i}]: entrypoint must be non-empty.",
                    "spec_json",
                )
        return ValidationResult(True, "info", f"Valid spec JSON ({len(specs)} spec(s)).", "spec_json")

    def _validate_c_source(self, content: bytes) -> ValidationResult:
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return ValidationResult(False, "error", "File is not valid UTF-8 text.", "binary")
        # Server-side clang check is not done here (requires DockerRunner)
        return ValidationResult(True, "info", "C source file accepted (syntax check requires container).", "c_source")

    def _validate_ql(self, content: bytes) -> ValidationResult:
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return ValidationResult(False, "error", "File is not valid UTF-8 text.", "binary")
        return ValidationResult(True, "info", "QL file accepted (compile check requires container).", "ql_source")

    def _validate_ktest(self, content: bytes) -> ValidationResult:
        if len(content) < 5 or content[:5] != b"KTEST":
            return ValidationResult(
                False, "error",
                'File does not start with "KTEST" magic bytes — not a valid .ktest file.',
                "unknown",
            )
        if len(content) == 0:
            return ValidationResult(True, "warning", ".ktest file is empty.", "ktest")
        return ValidationResult(True, "info", "Valid .ktest file.", "ktest")

    def _validate_bitcode(self, content: bytes) -> ValidationResult:
        if len(content) < 2 or content[:2] != b"BC":
            return ValidationResult(
                False, "error",
                'File does not start with "BC" magic bytes (0x42 0x43) — not valid LLVM bitcode.',
                "unknown",
            )
        return ValidationResult(True, "info", "Valid LLVM bitcode file.", "llvm_bitcode")

    def _sniff_format(self, content: bytes) -> str:
        if content[:4] == b"%PDF":
            return "pdf"
        if content[:4] in (b"\x7fELF",):
            return "elf"
        if content[:2] in (b"PK",):
            return "zip"
        try:
            content.decode("utf-8")
            return "json"
        except UnicodeDecodeError:
            return "binary"


_validator_service = ValidatorService()


def get_validator_service() -> ValidatorService:
    return _validator_service
