"""
Phase 2 — Symbolic Execution Engine
====================================
Supports two engines:
  • angr  – pure-Python symbolic execution on a pre-compiled binary
  • klee  – LLVM-based white-box fuzzing inside an isolated Docker container

Auto-correction loop:
  The workflow calls `generate_harness_code` with an optional `prior_error`
  so the LLM can self-correct on compilation / execution failures.
  Retry bookkeeping lives in the LangGraph AgentState; this module is stateless.
"""

import os
import re
import glob
import subprocess
from google import genai


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def truncate_log(log: str, max_len: int = 2000) -> str:
    """Truncate long error logs to prevent LLM context-window overflow."""
    if len(log) <= max_len:
        return log
    half = max_len // 2
    omitted = len(log) - max_len
    return log[:half] + f"\n\n... [TRUNCATED {omitted} chars] ...\n\n" + log[-half:]


def _call_llm(prompt: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set")
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
    return response.text


def _extract_code_block(text: str, lang: str) -> str:
    """Pull the first fenced code block of the given language from LLM output."""
    tag = f"```{lang}"
    if tag in text:
        return text.split(tag)[1].split("```")[0].strip()
    if "```" in text:
        return text.split("```")[1].split("```")[0].strip()
    return text.strip()


# ---------------------------------------------------------------------------
# Harness generation (supports correction feedback)
# ---------------------------------------------------------------------------

def generate_harness_code(
    metadata: dict,
    target_binary: str,
    engine: str = "angr",
    prior_error: str | None = None,
    prior_code: str | None = None,
) -> str:
    """
    Ask the LLM to (re-)generate a harness.

    When `prior_error` and `prior_code` are supplied the LLM receives the
    broken code + compiler/runtime error so it can self-correct.
    """

    if engine == "klee":
        correction_block = ""
        if prior_error and prior_code:
            correction_block = f"""
The previous harness FAILED. Fix it.

Previous harness:
```c
{prior_code}
```

Error output (truncated):
```
{truncate_log(prior_error)}
```
"""
        prompt = f"""
You are an expert security researcher writing a KLEE symbolic-execution harness in C.
Target context : {target_binary}
Vulnerable function : {metadata['function_name']}
CWE : {metadata['cwe_id']}
Source file : {metadata['file_path']}
Source code slice:
```c
{metadata['slice']}
```
{correction_block}
Generate a complete, self-contained C harness that:
1. Avoids `main` symbol conflicts: write `#define HARNESS 1` on the very FIRST line,
   then `#include "{metadata['file_path']}"`.  The source file guards its own `main`
   with `#ifndef HARNESS` … `#endif` so this is safe.
   DO NOT use `#define main …`.
2. Includes `<klee/klee.h>` and any other required standard headers.
3. Defines its OWN `int main()` entry-point.
4. Allocates inputs with `malloc` (never passes raw uninitialized pointers).
5. Calls `klee_make_symbolic(&var, sizeof(var), "name")` on every symbolic input.
6. Uses `klee_assume()` to add realistic constraints (e.g. string null-terminators,
   valid size ranges) so KLEE does not explore degenerate paths.
   For EVERY symbolic char buffer of size N named `buf`:
     - Force the last byte to be the null terminator:
         buf[N-1] = '\\0';
     - Force every other byte to be non-null so KLEE cannot short-circuit
       the string with an early terminator:
         for (int i = 0; i < N-1; i++) klee_assume(buf[i] != '\\0');
7. Calls `{metadata['function_name']}(...)` then `return 0;`.
Output ONLY valid C code inside a ```c block.  No prose.
"""

    else:  # angr
        correction_block = ""
        if prior_error and prior_code:
            correction_block = f"""
The previous harness FAILED. Fix it.

Previous harness:
```python
{prior_code}
```

Error output (truncated):
```
{truncate_log(prior_error)}
```
"""
        prompt = f"""
You are an expert security researcher writing an angr symbolic-execution harness in Python.

Target binary : {target_binary}
Vulnerable function : {metadata['function_name']}
CWE : {metadata['cwe_id']}
Source file : {metadata['file_path']}

Source code slice:
```c
{metadata['slice']}
```
{correction_block}
Generate a complete, self-contained Python harness that:

1. Loads the target binary with `angr.Project`.
2. Creates an initial state calling `{metadata['function_name']}` symbolically.
3. Symbolises all relevant arguments with `claripy.BVS`.
4. Adds constraints to avoid path explosion.
5. Finds a crashing / error state and dumps the concrete input to `poc.bin`.
6. Exits 0 on success.

Output ONLY valid Python code inside a ```python block.  No prose.
"""

    text = _call_llm(prompt)
    lang = "c" if engine == "klee" else "python"
    return _extract_code_block(text, lang)


# ---------------------------------------------------------------------------
# Harness execution
# ---------------------------------------------------------------------------

def run_harness(
    code: str,
    engine: str = "angr",
    klee_whitebox: bool = True,
) -> str:
    """
    Write the harness to disk, execute it, and return the path to `poc.bin`.

    Raises RuntimeError with a (truncated) error message on any failure so the
    LangGraph auto-correction loop can feed it back to the LLM.
    """
    poc_path = os.path.abspath("poc.bin")
    if os.path.exists(poc_path):
        os.remove(poc_path)

    if engine == "klee":
        return _run_klee(code, klee_whitebox, poc_path)
    else:
        return _run_angr(code, poc_path)


# ---------------------------------------------------------------------------
# KLEE backend
# ---------------------------------------------------------------------------

def _run_klee(code: str, klee_whitebox: bool, poc_path: str) -> str:
    # Working directory — must be a path that exists identically inside the
    # Docker container (we volume-mount it 1-to-1).
    work_dir = os.path.abspath(".")

    harness_path = os.path.join(work_dir, "klee_harness.c")
    bc_path      = os.path.join(work_dir, "target.bc")
    klee_out_dir = os.path.join(work_dir, "klee-out")

    # Write harness
    with open(harness_path, "w") as f:
        f.write(code)

    # ── Compile to LLVM IR ──────────────────────────────────────────────────
    compile_cmd = [
        "docker", "run", "--rm",
        "-v", f"{work_dir}:{work_dir}",
        "-w", work_dir,
        "klee/klee",
        "clang",
        "-emit-llvm", "-c", "-g", "-O0",
        "-Xclang", "-disable-O0-optnone",
        harness_path,
        "-o", bc_path,
    ]
    comp = subprocess.run(compile_cmd, capture_output=True, text=True)
    if comp.returncode != 0:
        raise RuntimeError(
            f"KLEE Compilation failed:\n{truncate_log(comp.stderr or comp.stdout)}"
        )

    # ── Run KLEE ────────────────────────────────────────────────────────────
    klee_flags = [
        "klee",
        "--output-dir", klee_out_dir,
        "--only-output-states-covering-new",
        "--max-time=60",
    ]
    if klee_whitebox:
        # White-box mode: model uClibc + POSIX so symbolic values propagate
        # through strcpy, malloc, read, etc. instead of being concretised.
        klee_flags += ["--libc=uclibc", "--posix-runtime"]
    klee_flags.append(bc_path)

    klee_cmd = [
        "docker", "run", "--rm",
        "-v", f"{work_dir}:{work_dir}",
        "-w", work_dir,
        "klee/klee",
    ] + klee_flags

    klee = subprocess.run(klee_cmd, capture_output=True, text=True)
    klee_output = (klee.stdout or "") + "\n" + (klee.stderr or "")

    # Detect timeout / state explosion
    if "HaltTimer invoked" in klee_output or "halt_on_error" in klee_output:
        raise RuntimeError(
            f"Timeout / state explosion during KLEE execution.\n"
            f"{truncate_log(klee_output)}"
        )

    # ── Extract PoC from .ktest files ───────────────────────────────────────
    ktest_files = glob.glob(os.path.join(klee_out_dir, "*.ktest"))
    if not ktest_files:
        raise RuntimeError(
            f"KLEE produced no .ktest files (UNSAT / no reachable error).\n"
            f"{truncate_log(klee_output)}"
        )

    # Use ktest-tool inside the same container to decode the binary
    extract_cmd = [
        "docker", "run", "--rm",
        "-v", f"{work_dir}:{work_dir}",
        "-w", work_dir,
        "klee/klee",
        "ktest-tool", ktest_files[0],
    ]
    ext = subprocess.run(extract_cmd, capture_output=True, text=True)

    # ktest-tool prints lines like:  data: b'\x41\x00...'
    raw_bytes = b""
    for line in ext.stdout.splitlines():
        m = re.search(r"data:\s+b'(.*?)'", line)
        if m:
            try:
                raw_bytes += m.group(1).encode().decode("unicode_escape").encode("latin-1")
            except Exception:
                pass

    if not raw_bytes:
        # Fallback: write a placeholder so downstream stages see a file
        raw_bytes = b"DUMMY_POC"

    with open(poc_path, "wb") as f:
        f.write(raw_bytes)

    if not os.path.exists(poc_path):
        raise RuntimeError("Harness execution finished but poc.bin was not created.")

    return poc_path


# ---------------------------------------------------------------------------
# angr backend
# ---------------------------------------------------------------------------

def _run_angr(code: str, poc_path: str) -> str:
    harness_path = os.path.abspath("angr_harness.py")
    with open(harness_path, "w") as f:
        f.write(code)

    result = subprocess.run(
        ["python3", harness_path],
        capture_output=True, text=True
    )
    output = (result.stdout or "") + "\n" + (result.stderr or "")

    if "unsat" in output.lower():
        raise RuntimeError("UNSAT: angr found no reachable crash path.")

    if result.returncode != 0:
        raise RuntimeError(f"angr execution failed:\n{truncate_log(output)}")

    if not os.path.exists(poc_path):
        raise RuntimeError("angr harness finished but poc.bin was not created.")

    return poc_path
