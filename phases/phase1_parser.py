"""
Phase 1 — SARIF Parser + Code Slicer
=====================================
Public API
----------
  parse_all_findings(sarif_path, source_dir) → list[dict]
      Parses ALL results from a SARIF file and returns a list of vulnerability
      metadata dicts (one per finding).  Findings whose source file or function
      cannot be located are silently skipped and logged to stderr.

  parse_sarif_and_extract_slice(sarif_path, source_dir) → dict
      Legacy single-result helper kept for backward compatibility.
      Returns the metadata for the FIRST parseable finding.
"""

import json
import os
import sys

import tree_sitter_c as tsc
from tree_sitter import Language, Parser


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_parser() -> Parser:
    C_LANGUAGE = Language(tsc.language())
    return Parser(C_LANGUAGE)


def _extract_function_at_line(source_code: str, start_line: int, parser: Parser) -> dict | None:
    """
    Return a dict with {function_name, start_line, end_line, slice} for the
    function definition that contains `start_line` (1-indexed).
    Returns None if no function is found.
    """
    tree = parser.parse(bytes(source_code, "utf8"))

    def traverse(node):
        if node.type == "function_definition":
            # tree-sitter is 0-indexed; SARIF is 1-indexed
            if node.start_point[0] <= start_line - 1 <= node.end_point[0]:
                return node
        for child in node.children:
            res = traverse(child)
            if res:
                return res
        return None

    target_node = traverse(tree.root_node)
    if target_node is None:
        return None

    slice_code = source_code[target_node.start_byte : target_node.end_byte]

    # Extract the function name from the declarator child
    func_name = "unknown_function"
    for child in target_node.children:
        if child.type == "function_declarator":
            for subchild in child.children:
                if subchild.type == "identifier":
                    func_name = source_code[subchild.start_byte : subchild.end_byte]
                    break
            break

    return {
        "function_name": func_name,
        "start_line": target_node.start_point[0] + 1,
        "end_line": target_node.end_point[0] + 1,
        "slice": slice_code,
    }


def _parse_single_result(result: dict, source_dir: str, parser: Parser) -> dict | None:
    """
    Attempt to convert one SARIF result entry into a vulnerability metadata dict.
    Returns None (and prints a warning) if any step fails.
    """
    try:
        location = result["locations"][0]["physicalLocation"]
        uri = location["artifactLocation"]["uri"]
        start_line = location["region"]["startLine"]
        cwe_id = result.get("ruleId", "Unknown")
    except (KeyError, IndexError) as e:
        print(f"[phase1] Skipping malformed SARIF result: {e}", file=sys.stderr)
        return None

    file_path = os.path.join(source_dir, uri)
    if not os.path.exists(file_path):
        print(f"[phase1] Skipping — source file not found: {file_path}", file=sys.stderr)
        return None

    try:
        with open(file_path, "r", errors="replace") as f:
            source_code = f.read()
    except OSError as e:
        print(f"[phase1] Skipping — cannot read {file_path}: {e}", file=sys.stderr)
        return None

    func_info = _extract_function_at_line(source_code, start_line, parser)
    if func_info is None:
        print(
            f"[phase1] Skipping — no function found at line {start_line} in {file_path}",
            file=sys.stderr,
        )
        return None

    return {
        "file_path": file_path,
        "cwe_id": cwe_id,
        **func_info,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_all_findings(sarif_path: str, source_dir: str) -> list[dict]:
    """
    Parse ALL results from a SARIF file.

    Returns a list of vulnerability metadata dicts — one per parseable finding.
    Findings that cannot be resolved (missing file, no function, malformed) are
    skipped with a stderr warning rather than raising an exception, so the
    pipeline continues to process the remaining findings.
    """
    with open(sarif_path, "r") as f:
        sarif_data = json.load(f)

    parser = _build_parser()
    findings: list[dict] = []

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            meta = _parse_single_result(result, source_dir, parser)
            if meta is not None:
                findings.append(meta)

    return findings


def parse_sarif_and_extract_slice(sarif_path: str, source_dir: str) -> dict:
    """
    Legacy single-finding helper.
    Raises ValueError if no parseable finding exists.
    """
    findings = parse_all_findings(sarif_path, source_dir)
    if not findings:
        raise ValueError("No parseable vulnerability findings in SARIF file.")
    return findings[0]
