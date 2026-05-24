Phase 1: Static Analysis

**Input**: C/C++ project source root + build configuration
**Output**: `Phase1Result` containing a list of `VulnerabilitySpec`

#### Internal Pipeline

```
[Fact Generation]
  Build CodeQL DB → run 34 queries → collect SARIF findings
          ↓
[Fact Enrichment]
  Apply 5 regex-based extractors → produce FactPack per finding
          ↓
[Specification Generation]
  Select entry point + assign assertion template + filter → VulnerabilitySpec JSON
```

#### Data Models (`sailor/models/schemas.py` — Pydantic v2)

```python
class Location(BaseModel):
    file: str
    line: int
    col_start: int
    col_end: int

class TraceStep(BaseModel):
    file: str
    line: int
    col: int
    label: Literal["source", "step", "sink"]

class SARIFFinding(BaseModel):
    finding_id: str        # "<rule_id>:<file>:<line>:<col>"
    rule_id: str
    cwe: str               # e.g. "CWE-120"
    location: Location
    description: str
    trace: list[TraceStep]
    snippet: str           # source line at ℓ, max 120 chars

class BuildContext(BaseModel):
    include_paths: list[str]   # all -I<path> flags
    defines: list[str]         # all -D<MACRO> flags

class FactPack(BaseModel):
    finding: SARIFFinding
    suspect_calls: list[str]
    pointer_vars: list[str]
    length_vars: list[str]
    bounds_hints: list[str]
    build_context: BuildContext

class VulnerabilitySpec(BaseModel):
    rule_id: str
    cwe: str
    file: str
    line: int
    col: int
    message: str
    snippet: str
    trace: list[TraceStep]
    suspect_calls: list[str]
    pointer_vars: list[str]
    length_vars: list[str]
    bounds_hints: list[str]
    build_context: BuildContext
    entrypoint: str            # "LLM_INFER" or resolved function name
    assertion_template: str

class Phase1Result(BaseModel):
    project: str
    project_root: str
    total_findings: int
    after_filtering: int
    reduction_rate: float
    by_cwe: dict[str, int]
    specifications: list[VulnerabilitySpec]
    timestamp: str             # ISO 8601
```

#### CodeQL Query Suite — 34 Queries

| Category | CWEs | Count | Type |
|----------|------|-------|------|
| Memory corruption | 120, 121, 125, 476, 787 | 6 | Standard |
| Integer overflow | 190 | 4 | Standard |
| UAF / double-free | 415, 416, 562 | 3 | Standard |
| Buffer overflow | 120, 125, 787, 823 | 6 | Custom |
| Null dereference | 476 | 1 | Custom |
| Uncontrolled recursion | 674 | 1 | Custom |
| Use-after-free (variants) | 416 | 6 | Custom |
| Stale pointer / type confusion | 416, 125 | 5 | Custom |
| Lifetime mismatch | 416 | 2 | Custom |

Custom query template (CWE-120 example — implement all 21 similarly):

```ql
/**
 * @name CWE-120: Unchecked length in memory-copy call
 * @id local/cpp/cwe-120-overflow
 * @kind problem
 * @severity error
 */
import cpp

predicate isWriteFunc(Function f) {
  f.getName().regexpMatch("(?i)^(memcpy|memmove|memset|strncpy|strncat)$")
}
predicate isSizeofLike(Expr e) { e instanceof SizeofExprOperator }
predicate isStringBound(Expr e) { e.toString().regexpMatch(".*(strlen|strnlen).*") }

from FunctionCall fc, Function f, Expr n
where fc.getTarget() = f
  and isWriteFunc(f)
  and n = fc.getArgument(2)
  and not isStringBound(n)
  and not isSizeofLike(n)
select fc, "CWE-120: Buffer Overflow via " + f.getName() + " (unchecked length)."
```

#### Fact Enrichment — 5 Extractors

| Extractor | Scope | Regex Pattern | Output Field |
|-----------|-------|--------------|--------------|
| Suspect Calls | Full function body | `\b([a-zA-Z_]\w*)\s*\(` | `suspect_calls` |
| Pointer Vars | Declaration lines | `[\w\s]+\*+\s+(\w+)` | `pointer_vars` |
| Length Vars | All lines | `\b(\w*(?:len\|size\|count\|capacity)\w*)\b` | `length_vars` |
| Bounds Hints | ℓ ± 20 lines | `\b\w+\s*(>=\|<=\|>\|<\|==\|!=)\s*[\w\(\)]+` | `bounds_hints` |
| Build Context | compile_commands.json | `-I`, `-D` flags | `build_context` |

Dangerous functions allowlist for Suspect Calls filter:

```python
DANGEROUS_FUNCTIONS = frozenset({
    "memcpy", "memmove", "memset", "strncpy", "strncat",
    "sprintf", "snprintf", "malloc", "calloc", "realloc",
    "free", "bfd_zalloc", "bfd_alloc", "alloca",
    "xmalloc", "xrealloc", "g_malloc", "g_realloc",
})
```

#### Assertion Templates (per CWE)

```python
ASSERTION_TEMPLATES: dict[str, str] = {
    "CWE-120": "n <= min(len(dst), len(src))",
    "CWE-121": "n <= min(len(dst), len(src))",
    "CWE-125": "n <= min(len(dst), len(src))",
    "CWE-787": "n <= min(len(dst), len(src))",
    "CWE-415": "no use of p after free(p)",
    "CWE-416": "no use of p after free(p)",
    "CWE-476": "p != NULL before *p",
    "CWE-190": "arithmetic within type range",
    "CWE-823": "offset within allocation bounds",
    "CWE-562": "no return of stack-local address",
    "CWE-674": "recursion depth bounded",
    # No match → "DERIVE_FROM_DESCRIPTION"
}
```

#### Filtering Rules

```python
# Discard if file path matches any of:
FILE_SKIP_PATTERNS = [
    r".*/test[s]?/.*",        r".*/testing/.*",
    r".*/bench(mark)?[s]?/.*",
    r".*/example[s]?/.*",     r".*/demo[s]?/.*",
    r".*/fuzz.*/.*",          r".*/oss-fuzz/.*",
    r".*\.gen\.(c|cpp)$",    r".*/vendor/.*",
    r".*/third[_-]party/.*",  r".*/external/.*",
]

# Discard if vulnerable function name matches any of:
FUNCTION_SKIP_PATTERNS = [
    r"^main$",
    r"^test_", r"_test$",
    r"^check_", r"^bench_", r"^perf_", r"^mock_",
    r"^__builtin_", r"^__asan_", r"^__ubsan_", r"^__sanitizer_",
]

# Reference result: binutils → 19,140 findings → 1,260 active targets (93% reduction)
```

#### Entry Point Selection (LLM_INFER mode)

```
1. Identify vulnerable function f_v containing ℓ
2. Walk call graph upward via BFS from f_v
3. Select nearest non-static, non-skipped caller as candidate
4. Record entrypoint = "LLM_INFER"
   (Phase 2 LLM may override during source exploration)
```

#### Integration Entry Point

```python
from sailor import Phase1Pipeline, Phase1Config

config = Phase1Config(
    project_name="binutils",
    project_root=Path("/path/to/project"),
    output_dir=Path("/path/to/output"),
    build_command="make -j8",
)
result: Phase1Result = Phase1Pipeline(config).run()
# Pass result.specifications to Phase 2
```

#### Output Files (written to `output_dir`)

```
findings.json          # after Fact Generation
fact_packs.json        # after Fact Enrichment
specifications.json    # after Specification Generation
phase1_summary.json    # statistics summary
```