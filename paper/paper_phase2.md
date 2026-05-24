# paper_phase2.md — Sailor Phase 2: LLM-Orchestrated Symbolic Execution

---

## Phase 2 Overview

```
Input:  VulnerabilitySpec (from Phase 1)
Output: One of three outcomes:
  (a) bug_triggered          → .ktest witness inputs  → Phase 3
  (b) inconclusive           → T_max turn budget exhausted
  (c) likely_false_positive  → site reached but no bug after R_max
                               additional refinement turns

Harness H = (Driver, Code Slice, Assertions)
  Driver      main() that sets up symbolic state and calls entry e
  Code Slice  self-contained C file with stubs along chain e → ℓ
  Assertions  reachability check + safety-property encoding
```

---

## Algorithm 1: LLM-Orchestrated Harness Synthesis

```
Input:   VulnerabilitySpec spec_i, project source P
Output:  Concrete test inputs OR inconclusive

Default budgets:
  T_explore = 8    source exploration turns
  T_author  = 12   harness authoring deadline
  T_max     = 60   total turn budget
  T_klee    = 300s per KLEE run
  R_max     = 15   refinement limit after site reached

t ← 0;  refine_count ← 0

while t < T_max:
  action ← LLM(plan, history)

  if t < T_explore:
    # Source exploration: tool calls into project source
    Execute source search / read / extract

  elif t < T_author:
    # Harness authoring: produce driver, code slice, stubs, assertions
    Write or modify H

  else:
    # Compile-execute-refine loop
    result ← CompileDiagnose(H, P)
    if result == diagnostic:
      Feed diagnostic to LLM
      t += 1; continue                   # compile failure consumes 1 turn

    (outcome, diag) ← ExecDiagnose(bitcode)

    if outcome == bug_triggered:
      return concrete_test_inputs        # → Phase 3

    if outcome == site_reached:
      refine_count += 1
      if refine_count > R_max:
        return likely_false_positive
      Feed diag back to LLM

  t += 1

return inconclusive                      # T_max exhausted
```

---

## §4.1 Driver Synthesis

The driver is the `main()` that constructs the initial symbolic state
from which KLEE explores paths toward ℓ.

### Source Exploration Phase (t < T_explore)

LLM issues tool calls to retrieve from project source:
- Function signatures
- Struct definitions
- Type declarations

### Decision 1: Entry Function Selection

```
LLM uses entrypoint strategy from spec (default LLM_INFER).
Retrieves e's signature to determine parameter types and how to
allocate arguments. May override initial e if source exploration
reveals a better entry point.
```

### Decision 2: Symbolic Input Classification

```
(a) Symbolic scalars
    Fields appearing in the vulnerability condition
    → klee_make_symbolic(&field, sizeof(field), "name")

(b) Concrete pointers
    Pointer fields allocated via calloc/malloc so KLEE can dereference
    without spurious null-pointer errors
    → p = calloc(1, sizeof(*p))

(c) Symbolic buffers
    Heap regions whose contents are symbolic; pointer itself concrete
    → buf = malloc(N); klee_make_symbolic(buf, N, "name")
```

### Decision 3: Guard Conditions

```
LLM identifies conditionals along chain e → f_v that cause early exit
before reaching ℓ:
  example: if (p == NULL) return;

For each guard condition c, the driver encodes:
  klee_assume(¬c)
  example: klee_assume(ptr != NULL)
```

### Driver Prompt Structure

```
SPEC:
  l: elfxx-x86.c:2699
  e: _bfd_x86_elf_late_size_sections
  d: CWE-120: unchecked memcpy length
  guards: plt_eh_frame==NULL, contents==NULL
  assert: n <= min(len(dst), len(src))

DRIVER RULES:
  Entry:    call e with allocated parameters
  Symbolic: overapproximate; make fields symbolic
    GOOD: klee_make_symbolic(&ctx, sizeof(ctx), "ctx");
    BAD:  ctx->state = 7;          // hardcoded → limits KLEE
  Guards:   for each guard c, add klee_assume(!c)
    GOOD: klee_assume(ptr != NULL);
  Pointers: real allocs, never NULL
    GOOD: p = calloc(1, sizeof(*p));
  Buffers:  alloc + make contents symbolic
    GOOD: buf = malloc(N); klee_make_symbolic(buf, N, "buf");
```

### Generated Driver (Running Example)

```c
int main() {
  bfd *out = calloc(1, sizeof(bfd));                       // (1) alloc
  struct bfd_link_info *info = calloc(1, sizeof(struct bfd_link_info));
  global_htab = calloc(1, sizeof(struct elf_x86_link_hash_table));

  global_htab->plt_eh_frame = calloc(1, sizeof(asection)); // (2) guard bypass

  unsigned char *dst = malloc(16);                         // (3) symbolic buffer
  klee_make_symbolic(dst, 16, "dst_bytes");
  global_htab->plt_eh_frame->contents = dst;               // (4) guard bypass

  unsigned char *src = malloc(512);
  klee_make_symbolic(src, 512, "src_bytes");
  global_htab->plt.eh_frame_plt = src;

  size_t sz;                                               // (5) symbolic scalar
  klee_make_symbolic(&sz, sizeof(sz), "copy_size");
  global_htab->plt_eh_frame->size = sz;

  _bfd_x86_elf_late_size_sections(out, info);              // (6) call e
  return 0;
}
```

Fields the driver touches (out of 40+ in `elf_x86_link_hash_table`):
- `plt_eh_frame`  → concrete pointer (guard bypass)
- `contents`      → concrete pointer (guard bypass) + symbolic buffer
- `size`          → symbolic scalar (overflow-condition variable)

Remaining fields: zero-initialized by `calloc`.

---

## §4.2 Stub Synthesis

The code slice is a self-contained C file containing only the code
along chain e → ℓ, with external dependencies replaced by stubs.

### Four Stub Granularities

#### (1) Function-level
```
Off-path callees → stubs matching original signature

If stub's return value influences path to ℓ (controls a branch):
  → return symbolic via klee_make_symbolic
    GOOD: int f(...) { int r;
                       klee_make_symbolic(&r, sizeof(r), "r");
                       return r; }
  BAD:  int f(...) { return -300; }  // hardcoded → limits exploration

Else: return a hardcoded default.

CWE-416 EXCEPTION:
  free() stub MUST call the real free() so the free-then-use
  sequence remains intact.
```

#### (2) Branch-level
```
Off-path if blocks    → if(0) { }
Off-path switch cases → break
```

#### (3) Loop-level
```
Loops enclosing target statement → single-pass if conditional (if(1))
→ bounds KLEE's path count
```

#### (4) Type-level
```
Project structs → redefined with only fields accessed by sliced code
→ avoids transitive type dependencies
→ enables standalone compilation
```

### Coverage Probes

```c
// Added at entry of every function in the slice:
klee_warning_once("SPINE_PROBE:<func>:ENTRY");

// Phase 2 uses these to diagnose not_reached:
//   "Entered: [f1, f2]   Missed: [f3]"
//   → LLM fixes driver or stubs for f3
```

### Code Slice Prompt Structure

```
SPEC:
  target:   memcpy at elfxx-x86.c:2699
  entry:    _bfd_x86_elf_late_size_sections
  on-path:  memcpy(htab->..->contents, .., ..->size)
  off-path: if-block(100+ lines), bfd_put_32, ...

CODE SLICE RULES:
  Entry:     keep signature + call to vul_func ONLY
    GOOD: int e(Type *ctx) { vul_func(ctx); return 0; }
  Branches:  off-path if → if(0), loop → if(1)
  Functions: off-path callees → symbolic stubs
  Types:     keep only fields accessed by sliced code
  Probes:    add klee_warning_once at entry of each func
  Exception: CWE-416 free() stub MUST call real free()
```

### Generated Code Slice (Running Example)

```c
// type-level: 40+ fields → 3
typedef struct asection { unsigned char *contents; size_t size; } asection;
struct elf_x86_link_hash_table {
  asection *plt_eh_frame;
  struct { unsigned char *eh_frame_plt; } plt;
};

// function-level: symbolic return
bfd_vma bfd_get_32(bfd *b, const void *p) {
  bfd_vma ret;
  klee_make_symbolic(&ret, sizeof(ret), "get32");
  return ret;
}

bool _bfd_x86_elf_late_size_sections(bfd *out, struct bfd_link_info *info) {
  klee_warning_once("SPINE_PROBE:...:ENTRY");
  struct elf_x86_link_hash_table *htab = g_htab;
  if (0) { /* branch-level: 100-line off-path block */ }
  if (1) { /* loop-level: single pass */
    memcpy(htab->plt_eh_frame->contents,
           htab->plt.eh_frame_plt,
           htab->plt_eh_frame->size);
    klee_assert(0 && "SAILOR_SINK_REACHED");  // reachability probe
  }
  return true;
}
```

---

## §4.3 Assertion Instantiation

Two complementary mechanisms encode the safety property in H.

### Mechanism 1: Reachability Assertion

```c
// Placed immediately after the vulnerable statement in code slice:
klee_assert(0 && "SAILOR_SINK_REACHED");

// KLEE fires this only if ℓ executes WITHOUT a memory error
//   → confirms ℓ is reachable (site_reached outcome)
// If KLEE detects memory error before this line
//   → bug_triggered outcome
```

### Mechanism 2: Vulnerability Condition

```
LLM reads the assertion template and adds klee_assume constraints
to the driver that VIOLATE the safety property.
KLEE's native error detection then flags the violation at ℓ:
  out-of-bounds access → .ptr.err
  use-after-free       → .free.err
  null dereference     → .ptr.err
```

### Per-CWE Encoding Patterns

```c
// CWE-120 / CWE-125: n <= min(len(dst), len(src))
char *dst = malloc(16);         // undersized
char *src = malloc(512);        // larger
size_t sz;
klee_make_symbolic(&sz, sizeof(sz), "sz");
klee_assume(sz > 16);           // VIOLATE bound → OOB access
klee_assume(sz <= 512);         // keep src valid (no spurious error)
memcpy(dst, src, sz);           // KLEE: .ptr.err

// CWE-416: no use of p after free(p)
obj_t *p = malloc(sizeof(obj_t));
klee_make_symbolic(p, sizeof(*p), "obj");
free(p);                        // (free() stub MUST call real free)
func_that_dereferences(p);      // KLEE: .free.err

// CWE-476: p != NULL before *p
struct ctx *p = NULL;
func_that_dereferences(p);      // KLEE: .ptr.err
```

### Running Example Instantiation

```
template: n <= min(len(dst), len(src))

Operand binding:
  n   = sz            (symbolic scalar declared in driver)
  dst = contents      (16-byte allocation in driver)
  src = eh_frame_plt  (512-byte allocation in driver)

Violation conditions added to driver:
  klee_assume(sz > 16);     // dst boundary violated → OOB write
  klee_assume(sz <= 512);   // src boundary preserved

KLEE result: out-of-bounds write at memcpy
Witness:     copy_size = 17
```

---

## §4.4 Harness Refinement

### CompileDiagnose(H, P)

```
Compile pipeline:
  clang -O0 -g -emit-llvm -c <driver, slice>  → .bc files
  llvm-link                                    → harness.bc

On failure, pattern-match the error into one of four classes:

  incomplete_type      → search project headers for missing struct/field,
                         present found definition to LLM
  conflicting_proto    → grep project for real prototype, present to LLM
  redefinition         → suggest #ifndef guard or stub removal
  other                → return raw error with file:line context
```

### ExecDiagnose(bitcode)

```
KLEE settings:
  search strategy: dual-strategy (random-path + depth-first)
  per-run timeout: T_klee = 300s
  depth limit:     1,000

Outcome classification:
  not_reached:   ℓ was not executed
                 → orchestrator reports which functions in the call
                   chain were entered (via klee_warning_once probes)
                   and which were not
                 → LLM fixes driver or stubs

  site_reached:  klee_assert(0) fires (ℓ reached, no memory error)
                 → LLM may tighten driver constraints
                 → if refine_count > R_max → likely_false_positive

  bug_triggered: KLEE detects memory safety violation at ℓ
                 → .ktest witness files produced → Phase 3
```

### Turn Budget Allocation

```
T_max = 60 total turns
  t <  T_explore (8):  Source exploration (tool calls)
  t <  T_author  (12): Harness authoring (write driver, slice, stubs, assertions)
  t >= T_author:       Compile-execute-refine loop
                         Each compile failure → 1 turn
                         Each KLEE run        → 1 turn
                         site_reached counter capped at R_max = 15
```

### Termination

```
bug_triggered                       → return .ktest witness → Phase 3
t >= T_max (60 turns)               → inconclusive
site_reached, refine_count > R_max  → likely_false_positive
```

### Refinement Example (Running Example)

```
Round 2 — Compile failure (incomplete_type):
  error: no member 'size' in 'struct asection'
  [DIAGNOSIS] INCOMPLETE TYPE
  [AUTO-FOUND] struct asection { *contents; size_t size; }
  FIX: Add 'size' field to type-level stub.

Round 3 — Compile failure (conflicting_proto):
  error: conflicting types for 'bfd_get_32'
  [DIAGNOSIS] CONFLICTING TYPES
  REAL PROTOTYPE: bfd_vma bfd_get_32(const void *)
  FIX: Remove stub (KLEE auto-stubs with return 0).

Round 5 — SE feedback (not_reached):
  SPINE: entry REACHED, memcpy sink NOT REACHED
  CAUSE: Guard if(plt_eh_frame != NULL) neutralized too aggressively
         (replaced with if(1)).
  FIX: Retain guard in slice; add klee_assume in driver.
    BEFORE: if (1) { memcpy(...); }
    AFTER:  if (htab->plt_eh_frame != NULL && ..->contents)
            { memcpy(...); }
          + driver: klee_assume(plt_eh_frame != NULL);
                    klee_assume(contents     != NULL);

Round 6 — BUG TRIGGERED:
  .ptr.err: memcpy OOB write, copy_size=17 > 16-byte dst.
```

### Phase 2 Output Artifacts

```
Error Report:
  Error: out of bound ptr
  File:  memcpy.c:17
  Stack: #0 memcpy()
         #1 .._late_size_sections()  stubs.c:27 → elfxx-x86.c:2710
         #2 main()                   driver.c:24

Execution Log:
  KLEE: WARNING ONCE: SPINE_PROBE:.._late_size..:ENTRY
  KLEE: ERROR: memcpy.c:17 memory error: out of bound pointer
  KLEE: NOTE: now ignoring this error at location
  KLEE: done: 48 paths explored, 1 error

Witness Inputs (.ktest):
  obj 0: 'dst_bytes'  size: 16
  obj 1: 'src_bytes'  size: 512
  obj 2: 'copy_size'  size: 8   data: 0x11 = 17

Path Constraints:
  array copy_size[8] : w32 → w8 = symbolic
  (Ugt (ReadLSB w64 0 copy_size) 16)
  (Ule (ReadLSB w64 0 copy_size) 512)
```
