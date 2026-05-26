import type { PipelineFunctionId } from "@/shared/contracts/sailor.types";

export const pipelineLabels: Record<PipelineFunctionId, string> = {
  phase1_db_build:                 "CodeQL DB Build",
  phase1_query_execution:          "Query Execution",
  phase1_sarif_parsing:            "SARIF Parsing",
  phase1_fact_enrichment:          "Fact Enrichment",
  phase1_spec_generation:          "Spec Generation",
  phase2_spec_selection:           "Spec Selection",
  phase2_source_exploration:       "Source Exploration",
  phase2_driver_synthesis:         "Driver Synthesis",
  phase2_stub_synthesis:           "Stub Synthesis",
  phase2_compile_diagnose:         "Compile & Diagnose",
  phase2_klee_execution:           "KLEE Execution",
  phase3_replay_driver_generation: "Replay Driver Generation",
  phase3_asan_compilation:         "ASan Compilation",
  phase3_result_classification:    "Result Classification",
};
