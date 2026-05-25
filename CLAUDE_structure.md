### Module Structure

```
sailor/
├── phase1/
│   ├── schemas.py
│   ├── wrapper.py              # CodeQLRunner extension
│   ├── queries.py              # custom QL queries
│   ├── fact_generation.py      # CodeQL → facts
│   ├── fact_enrichment.py      # user-guided heuristic enrichment
│   ├── spec_generation.py      # VulnerabilitySpec generation
│   └── pipeline.py             # Phase 1 orchestrator
├── phase2/
│   ├── schemas.py              # SE schemas
│   ├── source_explorer.py      # LLM source reading
│   ├── driver_synthesizer.py   # main() synthesis
│   ├── stub_synthesizer.py     # slice + stubs
│   ├── compile_diagnoser.py    # clang diagnostics
│   ├── se_diagnoser.py         # KLEE diagnostics
│   ├── harness_refiner.py      # refinement loop
│   ├── llm_orchestrator.py     # turn-based orchestration
│   └── pipeline.py             # Phase 2 orchestrator
└── phase3/
    ├── schemas.py              # Validation schemas
    ├── harness_runner.py       # Concrete replay
    ├── crash_detector.py       # Crash analysis
    ├── sanitizers.py           # Sanitizer integration
    └── pipeline.py             # Phase 3 orchestrator
```