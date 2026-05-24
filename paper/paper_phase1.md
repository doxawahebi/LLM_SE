# paper_phase1.md — Sailor Phase 1: Static Analysis Informed Target Generation

---

## Phase 1 Overview

```
Input:  C/C++ project source + build configuration
Output: List<VulnerabilitySpec>  (self-contained JSON documents)

Three stages:
  [Fact Generation]      CodeQL DB + 34 queries  → SARIF findings
          ↓
  [Fact Enrichment]      regex extractors        → fact pack (code-level hints)
          ↓
  [Spec Generation]      entry point + assertion template + filtering
                                                 → VulnerabilitySpec JSON
```

---

## Stage 1: Fact Generation

### CodeQL Database Build

```bash
# With compile_commands.json:
codeql database create <db> --language=cpp --build-mode=none

# With project build command:
codeql database create <db> --language=cpp --command=<build_cmd>
```

`compile_commands.json` is consumed downstream by Stage 2 to extract
`-I` and `-D` flags for the build context field of the spec.

### Query Suite (34 queries)

| Category                        | CWEs                    | # | Source            |
|---------------------------------|-------------------------|---|-------------------|
| Memory corruption               | 120, 121, 125, 476, 787 | 6 | codeql/cpp-queries |
| Integer overflow                | 190                     | 4 | codeql/cpp-queries |
| UAF / double-free               | 415, 416, 562           | 3 | codeql/cpp-queries |
| Buffer overflow                 | 120, 125, 787, 823      | 6 | custom             |
| Null dereference                | 476                     | 1 | custom             |
| Uncontrolled recursion          | 674                     | 1 | custom             |
| Use-after-free (5 variants + realloc) | 416               | 6 | custom             |
| Stale pointer / type confusion  | 416, 125                | 5 | custom             |
| Lifetime mismatch               | 416                     | 2 | custom             |

Custom rules cover gaps in the standard suite:
- `memcpy(dst, src, len)` where `len` may exceed `sizeof(dst)`
  (standard CWE-120 only catches `buf[i]` patterns)
- sprintf/snprintf stack buffer overflows
- Out-of-range pointer offsets
- Finer-grained UAF variants:
  free-then-dereference, free-then-call-argument, realloc-induced stale
- Lifetime and type-confusion patterns

### Finding Tuple

Each query produces one finding per flagged location:

```
f_i = (ℓ, d, τ)

ℓ  Candidate location  { file, line, col_start, col_end }
d  Vulnerability description (natural language; passed verbatim to LLM)
τ  Data-flow trace:
     inter-procedural query (e.g. UAF) → ⟨source, ..., sink⟩  full path
     local pattern query (e.g. unchecked length) → ⟨ℓ⟩        single point
```

### Custom Query Examples

```ql
-- (a) CWE-120: unchecked length in memory-copy call
predicate isWriteFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcpy|memmove|memset|strncpy|strncat)$")
}
from FunctionCall fc, Function f, Expr n
where fc.getTarget() = f
  and isWriteFunc(f)
  and countArg(fc, n)
  and not isStringBound(n)
  and not isSizeofLike(n)
select fc, "CWE-120: Buffer Overflow via " + f.getName() + " (unchecked length)."

-- (b) CWE-416: free-then-dereference (inter-procedural dataflow)
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node s) {
    exists(FunctionCall c, Expr a |
      isDirectFreeCall(c, a) and s.asExpr() = a)
  }
  predicate isSink(DataFlow::Node t) {
    exists(Expr e | isDerefUse(e) and t.asExpr() = e)
  }
}
module DF = DataFlow::Global<Cfg>;
```

The `select` clause emits the `d` description passed to the LLM in Phase 2.

### Running Example Result

```
Applied to binutils → flags memcpy at elfxx-x86.c:2699
  ℓ = elfxx-x86.c:2699:7
  d = "CWE-120: Buffer Overflow via memcpy (unchecked length)."
  τ = ⟨ℓ⟩   (local pattern → single point)
```

---

## Stage 2: Fact Enrichment

Applied to the function containing ℓ and the project build config.
Regex-based (no full AST) — fast and portable.

### Five Extractors

#### 1. Suspect Calls
```
Match:  function-call form: <identifier>(...
Filter: keep dangerous / allocation functions
        (memcpy, memmove, memset, strncpy, strncat, malloc, calloc,
         realloc, free, alloca, sprintf, snprintf, plus project-specific
         allocators like bfd_zalloc, xmalloc, g_malloc)

Output: "suspect_calls": ["memcpy", "bfd_zalloc", ...]
Purpose: directs Phase 2 LLM to the dangerous operation + allocation site
```

#### 2. Pointer Variables
```
Match:  pointer or array declarations in the function body

Output: "pointer_vars": ["contents", "buf", ...]
```

#### 3. Length Variables
```
Match:  identifiers whose names match size-related conventions:
        contains len / size / count / capacity (case-insensitive)
Exclude: all-caps tokens (treated as macros)

Output: "length_vars": ["size", "len", ...]
```

#### 4. Bounds Hints
```
Scope:  function body, around ℓ
Match:  comparison expressions (>=, <=, >, <, ==, !=)

Output: "bounds_hints": ["ivlen >= 0", "size < MAX_SIZE", ...]
Purpose: Phase 2 may reuse these as klee_assume constraints
```

#### 5. Build Context
```
Source: compile_commands.json entry for the file containing ℓ
Extract: -I<path> flags  → include_paths
         -D<MACRO> flags → defines

Output: "build_context": {
  "include_paths": ["-Ibfd", "-Iinclude", ...],
  "defines":       ["-DHAVE_CONFIG_H", ...]
}
Purpose: Phase 2 includes correct headers, resolves project-specific types
```

### Running Example Enrichment

```
Suspect calls near elfxx-x86.c:2699:
  memcpy                       ← dangerous copy (target)
  bfd_zalloc                   ← allocation site for `contents`
  bfd_put_32
  bfd_set_section_alignment

Build context:
  include_paths: ["-Ibfd"]    ← enables resolving elf_x86_link_hash_table
```

---

## Stage 3: Vulnerability Specification Generation

Three elements added to each (finding + fact pack):

### Element 1: Entry Point Selection

```
Default strategy: LLM_INFER

Procedure:
  1. Identify vulnerable function f_v containing ℓ
  2. Walk call graph upward from f_v
  3. Select nearest non-static caller as initial e
  4. Emit "entrypoint": "LLM_INFER" in spec
  5. Phase 2 LLM may override e during source exploration (§4.1)
     if a different entry better reaches ℓ

Other configurable strategies:
  - manual override (caller specifies e explicitly)
  - pure call-graph lookup (no LLM override)
```

### Element 2: Assertion Template

Looked up by CWE identifier extracted from `rule_id`:

| Vulnerability class          | CWEs               | Template                              |
|------------------------------|--------------------|---------------------------------------|
| Out-of-bounds read/write     | 120, 121, 125, 787 | n <= min(len(dst), len(src))          |
| Use-after-free / double-free | 415, 416           | no use of p after free(p)             |
| Stale pointer                | 416 (variants)     | p not dereferenced after realloc/free |
| Null dereference             | 476                | p != NULL before *p                   |
| Integer overflow             | 190                | arithmetic within type range          |
| Out-of-range offset          | 823                | offset within allocation bounds       |
| Return of stack address      | 562                | no return of stack-local address      |
| Uncontrolled recursion       | 674                | recursion depth bounded               |

No matching template → Phase 2 LLM derives the property from `d` + fact pack.

### Element 3: Filtering

Skip a finding if its file path or function name matches any pattern:

```
File path skip categories:
  test/ testing/ bench*/ example/ fuzz/ oss-fuzz/
  *.gen.c  vendor/  third-party/
  + project-specific CLI tool files (so only core library remains)

Function name skip categories:
  main
  test_*, _test
  check_*, bench_*, perf_*, mock_*
  __builtin_*, __asan_*, __ubsan_*
```

Example reduction (binutils): 19,140 findings → 1,260 active targets.

### Final VulnerabilitySpec JSON

```json
{
  "rule_id":            "local/cpp/cwe-120-overflow",
  "file":               "bfd/elfxx-x86.c",
  "line":               2699,
  "message":            "CWE-120: Buffer Overflow via memcpy (unchecked length).",
  "snippet":            "memcpy(htab->..->contents, ..eh_frame_plt, ..->size);",
  "trace":              [{"file": "bfd/elfxx-x86.c", "line": 2699}],
  "suspect_calls":      ["memcpy", "bfd_zalloc", "bfd_put_32"],
  "pointer_vars":       ["contents", "eh_frame_plt"],
  "length_vars":        ["size"],
  "bounds_hints":       [],
  "build_context":      {"include_paths": ["-Ibfd"], "defines": []},
  "entrypoint":         "LLM_INFER",
  "assertion_template": "n <= min(len(dst), len(src))"
}
```

Each spec is self-contained → Phase 2 processes specs independently
and in parallel.
