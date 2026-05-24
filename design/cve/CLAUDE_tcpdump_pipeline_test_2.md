# CLAUDE_tcpdump_pipeline_test.md
# Sailor Full Pipeline Validation — tcpdump-4.9.1
# Goal: Find any real vulnerability from SAST findings and generate a PoC

> Claude Code reads this file to validate the complete Sailor pipeline
> using pre-existing SAST artifacts from .tcmdump_sast/.
>
> PURPOSE:
>   Prove the Sailor pipeline works end-to-end by:
>     1. Ingesting pre-built SAST findings (bootp_sa.sarif)
>     2. Running Phase 2 (LLM + KLEE) on each finding
>     3. Running Phase 3 (ASan) on any bug_triggered result
>     4. Generating a concrete PoC file for the confirmed vulnerability
>
> SUCCESS CRITERION:
>   At least ONE finding from bootp_sa.sarif is confirmed by ASan,
>   AND a concrete PoC file (input that triggers the bug) is produced.
>   The specific CVE ID does NOT matter.
>
> All Absolute Rules defined in CLAUDE.md apply in full.

---

## Pre-built Artifacts

```
.tcmdump_sast/
├── bootp_sa.sarif   ← CodeQL findings (Phase 1 output, already done)
├── myqueries/       ← Custom CodeQL queries that produced the SARIF
└── tcpdump-db/      ← Pre-built CodeQL DB for tcpdump-4.9.1
```

```
These artifacts mean Phase 1 (CodeQL) is already complete.
This test begins at SARIF ingestion and runs Phase 2 + Phase 3 in full.
Do NOT rebuild the CodeQL DB.
Do NOT re-run CodeQL queries.
Use the pre-built artifacts directly.
```

---

## Pipeline Architecture for This Test

```
.tcmdump_sast/bootp_sa.sarif
          │
          ▼
[SARIF Ingestion]         Parse findings → SARIFFinding list
          │
          ▼
[Fact Enrichment]         Apply 5 regex extractors → FactPack per finding
          │
          ▼
[Spec Generation]         Entry point + assertion template + filtering
          │
          ▼
[Phase 2: LLM + KLEE]     For each spec → try to trigger bug
          │                 bug_triggered → proceed
          │                 failed → try next spec
          ▼
[Phase 3: ASan]           Replay witness against unmodified tcpdump source
          │
          ▼
[PoC Generation]          Convert witness input → standalone PoC file
          │
          ▼
[Validation Report]       confirmed verdict + PoC path + pipeline metrics
```

---

## Step 0. Pre-flight Validation

### 0-1. Verify SAST artifacts

```bash
ls -la .tcmdump_sast/
file .tcmdump_sast/bootp_sa.sarif
ls .tcmdump_sast/myqueries/
ls .tcmdump_sast/tcpdump-db/

python3 - << 'EOF'
import json

with open(".tcmdump_sast/bootp_sa.sarif") as f:
    sarif = json.load(f)

print("=== bootp_sa.sarif Summary ===")
for run in sarif["runs"]:
    tool = run["tool"]["driver"]["name"]
    results = run["results"]
    print(f"Tool: {tool}, Findings: {len(results)}")
    for i, r in enumerate(results):
        loc = r["locations"][0]["physicalLocation"]
        uri  = loc["artifactLocation"]["uri"]
        line = loc["region"]["startLine"]
        msg  = r["message"]["text"][:80]
        rule = r.get("ruleId", "unknown")
        print(f"  [{i}] {uri}:{line}  rule={rule}")
        print(f"       {msg}")
EOF
```

Expected output:
- At least 1 finding
- Each finding has file URI, line number, rule ID, message

### 0-2. Verify tcpdump source

```bash
find . -name "print-bootp.c" 2>/dev/null
find . -maxdepth 3 -name "tcpdump.c" 2>/dev/null

if ! find . -name "print-bootp.c" 2>/dev/null | grep -q .; then
    git clone https://github.com/the-tcpdump-group/tcpdump.git tcpdump-src
    cd tcpdump-src && git checkout tcpdump-4.9.1 && cd ..
fi

TCPDUMP_SRC=$(find . -name "print-bootp.c" -exec dirname {} \; | head -1)
echo "Project root: $TCPDUMP_SRC"
```

### 0-3. Verify toolchain

```bash
klee --version          || { echo "KLEE not found"; exit 1; }
clang --version         || { echo "clang not found"; exit 1; }
clang -fsanitize=address -x c /dev/null -o /dev/null \
    && echo "ASan OK"   || { echo "ASan not supported"; exit 1; }
python3 -c "import pydantic; print('pydantic', pydantic.__version__)"
python3 -c "from sailor.phase1.pipeline import Phase1Pipeline; print('sailor OK')"
```

### 0-4. Validate myqueries against tcpdump-db

```bash
for ql in .tcmdump_sast/myqueries/*.ql; do
    echo "=== Validating: $(basename $ql) ==="
    codeql query run \
        --database=.tcmdump_sast/tcpdump-db \
        --output=/tmp/$(basename $ql .ql).bqrs \
        "$ql" && echo "OK" || echo "FAILED: $ql"
done

for bqrs in /tmp/*.bqrs; do
    echo "=== $(basename $bqrs) ==="
    codeql bqrs decode --format=csv "$bqrs" | head -20
done
```

Validation:
- All queries execute without error
- Query results reference at least 1 location in tcpdump source
- Results overlap with locations in bootp_sa.sarif

---

## Step 1. Ingest bootp_sa.sarif → SARIFFinding List

```python
import json
from pathlib import Path
from sailor.phase1.fact_generation import FactGenerator
from sailor.phase1.pipeline import Phase1Config

with open(".tcmdump_sast/bootp_sa.sarif") as f:
    sarif_dict = json.load(f)

project_root = Path("tcpdump-src")

config = Phase1Config(
    project_name="tcpdump",
    project_root=project_root,
    output_dir=Path("output_dir/tcpdump_test/phase1"),
)
config.output_dir.mkdir(parents=True, exist_ok=True)

generator = FactGenerator(
    runner=None,
    query_suite=None,
    source_root=project_root,
    output_dir=config.output_dir,
)

findings = generator._parse_sarif(sarif_dict)
print(f"Parsed {len(findings)} findings")
for f in findings:
    print(f"  {f.finding_id}")
    print(f"  file={f.location.file}  line={f.location.line}")
    print(f"  cwe={f.cwe}  desc={f.description[:60]}")

out = {"total": len(findings), "findings": [f.model_dump() for f in findings]}
(config.output_dir / "findings.json").write_text(json.dumps(out, indent=2))
print(f"Written: {config.output_dir}/findings.json")
```

Validation:
- `len(findings) >= 1`
- Each finding has non-empty `location.file`, `location.line`, `description`
- `findings.json` written

If `_parse_sarif()` fails on the real SARIF format:
```python
import json
d = json.load(open(".tcmdump_sast/bootp_sa.sarif"))
# Inspect actual structure
print(json.dumps(d["runs"][0]["results"][0], indent=2))
# Fix _parse_sarif() field names to match actual SARIF output
# Re-run Step 1
```

---

## Step 2. Fact Enrichment

```python
from sailor.phase1.fact_enrichment import FactEnricher
from pathlib import Path
import subprocess, json

project_root = Path("tcpdump-src")

if not (project_root / "compile_commands.json").exists():
    print("Building compile_commands.json...")
    subprocess.run(["./configure"], cwd=project_root, check=True)
    subprocess.run(["bear", "--", "make", "-j4"],
                   cwd=project_root, check=True)

enricher = FactEnricher(
    source_root=project_root,
    compile_commands_path=project_root / "compile_commands.json",
)

fact_packs = []
failed = []
for finding in findings:
    try:
        fp = enricher.enrich(finding)
        fact_packs.append(fp)
        print(f"OK  {finding.finding_id}")
        print(f"    suspect_calls: {fp.suspect_calls}")
        print(f"    length_vars:   {fp.length_vars}")
        print(f"    bounds_hints:  {fp.bounds_hints[:2]}")
    except Exception as e:
        print(f"FAIL {finding.finding_id}: {e}")
        failed.append((finding.finding_id, str(e)))

print(f"\nEnriched: {len(fact_packs)}/{len(findings)}, Failed: {len(failed)}")

out = {"total": len(fact_packs),
       "fact_packs": [fp.model_dump() for fp in fact_packs]}
(Path("output_dir/tcpdump_test/phase1") / "fact_packs.json")\
    .write_text(json.dumps(out, indent=2))
```

Validation:
- `len(fact_packs) >= 1`
- `fact_packs.json` written

---

## Step 3. Spec Generation + Prioritization

```python
from sailor.phase1.spec_generation import SpecificationGenerator
from sailor.utils.call_graph import CallGraphBuilder
from sailor.utils.filters import SpecificationFilter
from pathlib import Path
import json

call_graph = CallGraphBuilder(Path("tcpdump-src")).build()
spec_filter = SpecificationFilter()
spec_gen = SpecificationGenerator(call_graph, spec_filter)

specs, stats = spec_gen.generate(fact_packs)

print(f"Before filter: {stats['total_before_filter']}")
print(f"After filter:  {stats['total_after_filter']}")

def priority_score(s):
    score = 0
    high_cwe = ["CWE-122", "CWE-787", "CWE-125", "CWE-120", "CWE-416"]
    for i, cwe in enumerate(high_cwe):
        if cwe in s.cwe:
            score += (len(high_cwe) - i) * 10
    for call in s.suspect_calls:
        if call in ["memcpy", "malloc", "free", "EXTRACT_16BITS"]:
            score += 5
    return score

specs_prioritized = sorted(specs, key=priority_score, reverse=True)

print(f"\nPrioritized specs:")
for i, s in enumerate(specs_prioritized):
    print(f"  [{i}] score={priority_score(s):3d}  {s.file}:{s.line}  {s.func}")
    print(f"       cwe={s.cwe}  template={s.assertion_template}")

out = {"count": len(specs),
       "specifications": [s.model_dump() for s in specs_prioritized]}
(Path("output_dir/tcpdump_test/phase1") / "specifications.json")\
    .write_text(json.dumps(out, indent=2))
```

Validation:
- `len(specs) >= 1`
- All specs have `assertion_template` set
- `specifications.json` written

If all specs filtered out:
```python
# Diagnose which skip pattern removed the spec
import re
for fp in fact_packs:
    loc = fp.finding.location
    for pat in SpecificationFilter.FILE_SKIP_PATTERNS:
        if re.search(pat, loc.file):
            print(f"FILTERED: {loc.file} matched pattern: {pat}")
# Add confirmed tcpdump source files to WHITELIST_FILES in SpecificationFilter
```

---

## Step 4. Phase 2 — LLM + KLEE (Iterative per Spec)

```
TOKEN BUDGET AWARENESS:
  Each spec costs ~$0.5-1.0 in LLM tokens at T_max=60.
  Try highest-priority spec first.
  Move to next spec only if current spec exhausts all fixes.
```

```python
from sailor.phase2.pipeline import Phase2Pipeline, Phase2Config
from sailor.models.schemas import SEOutcome
from pathlib import Path
import json

p2_config = Phase2Config(
    project_name="tcpdump",
    project_root=Path("tcpdump-src"),
    output_dir=Path("output_dir/tcpdump_test/phase2"),
    llm_model="claude-sonnet-4-5",
    klee_path="klee",
    clang_path="clang",
    T_max=60,
    T_explore=8,
    T_author=12,
    R_max=15,
)

bug_triggered_results = []
all_results = []

for i, spec in enumerate(specs_prioritized):
    print(f"\n=== Spec [{i}] {spec.file}:{spec.line} {spec.func} ===")

    results = Phase2Pipeline(p2_config).run([spec])
    all_results.extend(results)

    for r in results:
        print(f"  outcome={r.outcome}  turns={r.turns_used}")
        if r.outcome == SEOutcome.BUG_TRIGGERED:
            print(f"  *** BUG TRIGGERED — ktest={r.witness.ktest_paths}")
            bug_triggered_results.append((spec, r))

    if bug_triggered_results:
        print(f"\nBug found at spec [{i}] — stopping.")
        break

summary = {
    "specs_tried": i + 1,
    "bug_triggered": len(bug_triggered_results),
    "results": [r.model_dump() for _, r in bug_triggered_results],
    "all_outcomes": [
        {"spec": f"{s.file}:{s.line}", "outcome": r.outcome,
         "turns": r.turns_used}
        for s, r in zip(specs_prioritized[:i+1],
                        [r for _, r in zip(specs_prioritized, all_results)])
    ],
}
(Path("output_dir/tcpdump_test/phase2") / "phase2_summary.json")\
    .write_text(json.dumps(summary, indent=2))
```

### Driver Hint Injection (reduces wasted turns)

```python
def build_driver_hints(spec) -> list[str]:
    """
    Inject tcpdump-specific hints into Phase 2 LLM prompt.
    These encode domain knowledge so LLM does not waste
    exploration turns discovering basic tcpdump conventions.
    """
    hints = [
        "tcpdump uses netdissect_options *ndo as the first argument "
        "to all print functions. Allocate with calloc and set callbacks.",
        "Required ndo fields: ndo_printf, ndo_error, ndo_warning, "
        "ndo_default_print, ndo_snaplen=65535.",
    ]

    func = spec.func.lower()
    file = spec.file.lower()

    if any(k in func or k in file for k in ["bootp", "dhcp"]):
        hints += [
            "CRITICAL: ndo->ndo_vflag = 3 to reach the vulnerable path. "
            "Without this the function returns early before the bug.",
            "Set ndo->ndo_snapend = packet_buf + snap_size (symbolic). "
            "klee_assume(snap_size >= 44 && snap_size < pkt_len). "
            "This forces EXTRACT_16BITS to read past the allocation end.",
            "Call bootp_print(ndo, packet_buf, pkt_len) directly. "
            "Skip pcap_loop entirely.",
        ]
    if any(k in func or k in file for k in ["udp", "tcp", "ip"]):
        hints += [
            "ndo->ndo_vflag = 1 for verbose output paths.",
        ]
    if "EXTRACT_16BITS" in spec.suspect_calls \
            or "EXTRACT_32BITS" in spec.suspect_calls:
        hints += [
            "EXTRACT_*BITS reads N bytes past the current pointer. "
            "Trigger overflow by making ndo_snapend < pointer + N.",
        ]

    return hints
```

### Phase 2 Self-Healing Per Spec

```
For each spec, apply fixes in this order before moving to next spec.
Maximum 2 fix attempts per spec.

NOT_REACHED:
  Fix A: Verify ndo_vflag hint injected. If missing → add and re-run.
  Fix B: Simplify code slice — remove all code before the target stmt.
  Fix C: Reduce T_explore=4, use concrete values for non-critical fields.

SITE_REACHED (no bug):
  Fix A: klee_assume(snap_size == pkt_len - 1)  ← exact 1-byte overflow
  Fix B: Shrink pkt_len to match minimum packet size from SARIF snippet.

INCONCLUSIVE:
  Fix A: klee_depth_limit=50, make only the critical size variable symbolic.
  Fix B: Seed KLEE with concrete packet bytes from tcpdump test suite.

COMPILE_ERROR:
  → Match error pattern → apply specific fix immediately (no retry count)
  "incomplete type"        → add missing #include
  "conflicting types"      → grep real prototype and fix stub
  "undefined reference"    → add missing source file to compilation
```

---

## Step 5. Phase 3 — ASan Concrete Validation

```python
from sailor.phase3.pipeline import Phase3Pipeline, Phase3Config
from sailor.models.schemas import ValidationVerdict
from pathlib import Path
import json

if not bug_triggered_results:
    failure = {
        "verdict": "INCONCLUSIVE",
        "reason": "Phase 2 produced no bug_triggered results",
        "specs_tried": len(specs_prioritized),
    }
    Path("output_dir/tcpdump_test/failure_report.json")\
        .write_text(json.dumps(failure, indent=2))
    print("No bug triggered — written failure_report.json")
else:
    triggered_spec, triggered_result = bug_triggered_results[0]

    p3_config = Phase3Config(
        project_name="tcpdump",
        project_root=Path("tcpdump-src"),
        output_dir=Path("output_dir/tcpdump_test/phase3"),
        clang_path="clang",
        execution_timeout=30,
    )

    p3_result = Phase3Pipeline(p3_config).run(
        [triggered_result], [triggered_spec]
    )

    for r in p3_result.results:
        print(f"verdict:   {r.verdict}")
        print(f"asan_type: {r.asan_type}")
        print(f"file:      {r.file}:{r.line}")
        print(f"func:      {r.func}")
        print(f"inputs:    {r.inputs}")
```

### ASan Build for tcpdump

```bash
cd tcpdump-src

# Build unmodified source with ASan
./configure CC=clang CFLAGS="-fsanitize=address -O1 -g" \
            LDFLAGS="-fsanitize=address"
make -j4

# Create linkable archive for Phase 3
clang -fsanitize=address -O1 -g \
    -c print-bootp.c print-udp.c print-ip.c \
       print-ether.c netdissect.c util-print.c addrtoname.c \
    $(pkg-config --cflags libpcap 2>/dev/null || echo "") \
    -I. -I./missing
ar rcs libtcpdump_asan.a *.o
echo "ASan archive ready: $(ls -lh libtcpdump_asan.a)"
cd ..
```

### Phase 3 Self-Healing

```
Fix A — Crash only in replay_driver.c:
  ASanCompiler used stubs. Fix: explicitly include project .c files.
  Re-run Phase 3.

Fix B — ndo_vflag missing from replay_driver.c:
  grep "ndo_vflag" output_dir/tcpdump_test/phase3/*/replay_driver.c
  Fix: ReplayDriverGenerator._remove_klee_assume() must NOT strip
       regular assignments like ndo->ndo_vflag = 3.
  Re-run Phase 3.

Fix C — No crash at all:
  Read snap_size from .ktest. Must be < pkt_len.
  If snap_size >= pkt_len: go back to Phase 2 Fix A for that spec.

Fix D — ResultClassifier rejects extract.h:
  Update _is_project_source() to accept "extract.h" and "print-*.c".
  Re-run Phase 3.
```

---

## Step 6. PoC File Generation

```python
from pathlib import Path
import struct, json

confirmed = [r for r in p3_result.results
             if r.verdict.value == "CONFIRMED"]

if not confirmed:
    print("No confirmed results — cannot generate PoC")
else:
    result = confirmed[0]
    poc_dir = Path("output_dir/tcpdump_test/poc")
    poc_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating PoC for: {result.file}:{result.line} {result.func}")
    print(f"Witness: {result.inputs}")

    # Parse witness bytes
    witness = {v.name: bytes.fromhex(v.data_hex) for v in result.inputs}

    # 1. Copy replay_driver.c as PoC C source
    (poc_dir / "poc_reproducer.c")\
        .write_text(Path(result.replay_driver_path).read_text())

    # 2. Generate PCAP PoC (for packet parser vulnerabilities)
    pkt = (witness.get("bootp_packet")
           or witness.get("packet")
           or witness.get("buf")
           or b"\x00" * 64)

    pcap_global = struct.pack("<IHHiIII",
        0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pcap_pkt_hdr = struct.pack("<IIII",
        0, 0, len(pkt), len(pkt))

    pcap_path = poc_dir / "poc.pcap"
    pcap_path.write_bytes(pcap_global + pcap_pkt_hdr + pkt)
    print(f"PCAP PoC: {pcap_path} ({len(pkt)} bytes)")

    # 3. Generate trigger script
    trigger_sh = poc_dir / "trigger.sh"
    trigger_sh.write_text(
        f"#!/bin/bash\n"
        f"# Triggers confirmed vulnerability\n"
        f"# {result.asan_type} in {result.func}() at {result.file}:{result.line}\n\n"
        f"tcpdump -vvv -r poc.pcap\n"
        f"# Expected: AddressSanitizer: {result.asan_type}\n"
    )
    trigger_sh.chmod(0o755)

    # 4. Generate Python reproduce script
    witness_lines = "\n".join(
        f'    "{v.name}": bytes.fromhex("{v.data_hex}"),  # = {v.data_interpreted}'
        for v in result.inputs
    )
    script = f'''#!/usr/bin/env python3
"""
PoC for confirmed vulnerability in tcpdump-4.9.1
=================================================
File:      {result.file}
Function:  {result.func}
Line:      {result.line}
ASan type: {result.asan_type}

Witness inputs from KLEE symbolic execution:
{chr(10).join(f"  {v.name} = {v.data_interpreted}" for v in result.inputs)}

Reproduce:
  1. Build tcpdump-4.9.1 with ASan:
       ./configure CC="clang" CFLAGS="-fsanitize=address -O1 -g"
       make -j4
  2. python3 generate_poc.py
  3. ./tcpdump -vvv -r poc.pcap
  4. Observe: AddressSanitizer: {result.asan_type}
"""

import struct
from pathlib import Path

WITNESS = {{
{witness_lines}
}}

def build_packet():
    return (WITNESS.get("bootp_packet")
            or WITNESS.get("packet")
            or WITNESS.get("buf")
            or b"\\x00" * 64)

def write_pcap(pkt, path):
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    phdr = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
    Path(path).write_bytes(hdr + phdr + pkt)
    print(f"Written: {{path}} ({{len(pkt)}} bytes)")

if __name__ == "__main__":
    pkt = build_packet()
    write_pcap(pkt, "poc.pcap")
    print("\\nTrigger with: tcpdump -vvv -r poc.pcap")
    print(f"Expected:      AddressSanitizer: {result.asan_type}")
    print(f"Location:      {result.func}() at {result.file}:{result.line}")
'''
    (poc_dir / "generate_poc.py").write_text(script)
    (poc_dir / "generate_poc.py").chmod(0o755)

    print(f"\nPoC files in {poc_dir}:")
    for f in sorted(poc_dir.iterdir()):
        print(f"  {f.name}")
```

---

## Step 7. Pipeline Validation Checklist

```
All items must be checked for the pipeline to be VALIDATED.

SARIF Ingestion (Step 1):
  □ bootp_sa.sarif parsed without errors
  □ findings.json written with >= 1 entry
  □ All findings have file, line, description

Fact Enrichment (Step 2):
  □ fact_packs.json written with >= 1 fact pack
  □ At least one fact pack has non-empty suspect_calls
  □ At least one fact pack has non-empty build_context.include_paths

Spec Generation (Step 3):
  □ specifications.json written with >= 1 spec
  □ All specs have assertion_template set
  □ Priority ordering applied (higher CWE severity first)

Phase 2 — KLEE (Step 4):
  □ At least one spec produced outcome = "bug_triggered"
  □ .ktest witness files present in phase2/klee-out/
  □ turns_used <= 60 for bug_triggered spec
  □ phase2_summary.json written

Phase 3 — ASan (Step 5):
  □ verdict = "CONFIRMED" for at least one result
  □ asan_type = memory error type (heap-buffer-overflow etc.)
  □ Crash location is in tcpdump project source (NOT replay_driver.c)
  □ verified_bug.json written

PoC Generation (Step 6):
  □ output_dir/tcpdump_test/poc/ directory exists
  □ poc_reproducer.c present
  □ poc.pcap present
  □ generate_poc.py present and executable
  □ trigger.sh present with correct tcpdump invocation

myqueries Validation (Step 0-4):
  □ All .ql files executed without error against tcpdump-db
  □ Query results overlap with bootp_sa.sarif locations
```

---

## Step 8. Final Validation Report

```python
import json
from pathlib import Path

base = Path("output_dir/tcpdump_test")
report = {"pipeline": "Sailor", "project": "tcpdump-4.9.1"}

checks = [
    ("phase1/findings.json",       "total"),
    ("phase1/specifications.json", "count"),
    ("phase2/phase2_summary.json", "bug_triggered"),
]
for path, key in checks:
    p = base / path
    report[path] = json.loads(p.read_text()).get(key) \
        if p.exists() else "MISSING"

poc_dir = base / "poc"
report["poc_files"] = [f.name for f in poc_dir.iterdir()] \
    if poc_dir.exists() else []

vbug = base / "phase3" / "verified_bug.json"
if vbug.exists():
    v = json.loads(vbug.read_text())
    report["RESULT"] = "PIPELINE VALIDATED"
    report["confirmed_bug"] = {
        "asan_type": v.get("asan_type"),
        "file":      v.get("file"),
        "func":      v.get("func"),
        "cwe":       v.get("cwe"),
    }
else:
    report["RESULT"] = "PIPELINE NOT VALIDATED"
    frep = base / "failure_report.json"
    if frep.exists():
        report["failure"] = json.loads(frep.read_text())

print(json.dumps(report, indent=2))
(base / "validation_report.json").write_text(json.dumps(report, indent=2))
print(f"\nReport: {base}/validation_report.json")
```

---

## Claude Code Task Prompt

```
Read CLAUDE.md, then read CLAUDE_tcpdump_pipeline_test.md in full.

Your goal:
  Validate the Sailor pipeline end-to-end using pre-built SAST
  artifacts in .tcmdump_sast/.
  Find at least ONE real vulnerability from bootp_sa.sarif findings
  and generate a concrete PoC file that triggers it.
  A specific CVE ID is NOT required — any confirmed vulnerability counts.

EXECUTION MODEL:
  Run the steps in this file sequentially.
  When a step fails, apply the self-healing fixes for that step,
  re-run the step, then continue.
  Do NOT stop on first failure — exhaust fixes before giving up.

CRITICAL CONSTRAINTS:
  1. Do NOT rebuild .tcmdump_sast/tcpdump-db.
  2. Do NOT re-run CodeQL queries.
  3. Use _parse_sarif() to ingest bootp_sa.sarif directly (Step 1).
  4. Phase 3 MUST use unmodified tcpdump source compiled with ASan.
     Never use LLM-generated stubs in Phase 3 compilation.
  5. For any tcpdump verbose-output print function (bootp_print etc.):
     ndo->ndo_vflag = 3 MUST appear in the generated driver.
     Never remove this line during replay driver generation.

EXECUTION ORDER:
  Step 0 → Pre-flight: verify artifacts, source, toolchain, myqueries
  Step 1 → Ingest bootp_sa.sarif → SARIFFinding list
  Step 2 → Fact Enrichment → FactPack list
  Step 3 → Spec Generation + priority ordering
  Step 4 → Phase 2 (LLM + KLEE): iterate specs in priority order
  Step 5 → Phase 3 (ASan): replay witness against tcpdump source
  Step 6 → PoC Generation: poc.pcap + generate_poc.py + trigger.sh
  Step 7 → Pipeline Validation Checklist (all □ items)
  Step 8 → Generate validation_report.json

SUCCESS:
  verified_bug.json with verdict = "CONFIRMED"
  AND poc/ directory contains poc.pcap + generate_poc.py
  AND all □ items in checklist checked.

FAILURE:
  Write failure_report.json with:
    last_step_completed, failure_reason,
    specs_tried, fixes_attempted, recommendation.
```
