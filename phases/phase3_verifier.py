"""
Phase 3 — ASan Verifier
========================
Compiles the target source file (or uses a pre-compiled ASan binary),
injects the PoC input via stdin, and detects AddressSanitizer crash reports.

Compilation strategy (in priority order):
  1. If an `asan_binary` path is passed directly, use it as-is.
  2. If the source file is a plain self-contained C/C++ file, compile it with
     `gcc -fsanitize=address`.
  3. If the source directory contains a Makefile or CMakeLists.txt, the caller
     should pre-build and pass the resulting binary path.

Public API
----------
  verify_vulnerability(source_path, poc_path, asan_binary=None, extra_cflags="") → dict
"""

import os
import subprocess
import tempfile


def verify_vulnerability(
    source_path: str,
    poc_path: str,
    asan_binary: str | None = None,
    extra_cflags: str = "",
) -> dict:
    """
    Parameters
    ----------
    source_path : str
        Path to the vulnerable `.c` / `.cpp` source file.  Used to compile an
        ASan binary when `asan_binary` is not provided.
    poc_path : str
        Path to the raw PoC bytes (stdin input for the target binary).
    asan_binary : str, optional
        Pre-compiled binary with `-fsanitize=address`.  When provided, the
        compilation step is skipped entirely.
    extra_cflags : str
        Extra compiler flags appended when compiling from source (e.g. `-I./inc`).

    Returns
    -------
    dict with keys: verified (bool), rca_summary (str), full_trace (str)
    """
    # ── Step 1: Obtain / compile an ASan binary ──────────────────────────
    if asan_binary and os.path.isfile(asan_binary):
        binary_path = asan_binary
    else:
        binary_path = _compile_asan(source_path, extra_cflags)

    # ── Step 2: Load PoC bytes ───────────────────────────────────────────
    if not os.path.exists(poc_path):
        raise FileNotFoundError(f"PoC file not found: {poc_path}")
    with open(poc_path, "rb") as f:
        poc_data = f.read()

    # ── Step 3: Run target under ASan, feed PoC via stdin ────────────────
    env = os.environ.copy()
    # Disable ASLR-related randomisation so output is deterministic
    env["ASAN_OPTIONS"] = "abort_on_error=0:detect_stack_use_after_return=1"

    run_result = subprocess.run(
        [binary_path],
        input=poc_data,
        capture_output=True,
        timeout=30,
        env=env,
    )

    # ── Step 4: Parse ASan output ─────────────────────────────────────────
    asan_trace = run_result.stderr.decode("utf-8", errors="ignore")
    is_vulnerable = "ERROR: AddressSanitizer" in asan_trace

    rca_summary = "No AddressSanitizer error triggered."
    if is_vulnerable:
        for line in asan_trace.splitlines():
            if "ERROR: AddressSanitizer" in line:
                rca_summary = line.strip()
                break

    return {
        "verified":    is_vulnerable,
        "rca_summary": rca_summary,
        "full_trace":  asan_trace,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compile_asan(source_path: str, extra_cflags: str = "") -> str:
    """
    Compile `source_path` with ASan instrumentation.
    Uses clang if available, otherwise falls back to gcc.
    Returns the path to the compiled binary.
    """
    out_path = source_path + ".asan.out"

    # Determine compiler and language flags
    ext = os.path.splitext(source_path)[1].lower()
    is_cpp = ext in (".cpp", ".cc", ".cxx")

    # Try clang first (more precise ASan output); fall back to gcc
    for compiler in (["clang++"] if is_cpp else ["clang"], ["g++"] if is_cpp else ["gcc"]):
        cmd = [
            *compiler,
            "-fsanitize=address",
            "-g", "-O0",
            "-fno-omit-frame-pointer",
        ]
        if extra_cflags:
            cmd += extra_cflags.split()
        cmd += [source_path, "-o", out_path]

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return out_path

    # Both compilers failed — raise with the last error
    raise RuntimeError(
        f"ASan compilation failed for {source_path}:\n{res.stderr}"
    )
