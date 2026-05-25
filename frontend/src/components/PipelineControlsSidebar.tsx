import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AutoCheckbox } from "./AutoCheckbox";
import { getAutoConfig, patchAutoConfig } from "@/api/client";

const PHASE1_FUNCTIONS: Array<[string, string]> = [
  ["phase1.codeql_db_build", "CodeQL DB Build"],
  ["phase1.query_execution", "Query Execution"],
  ["phase1.sarif_parsing", "SARIF Parsing"],
  ["phase1.fact_enrichment", "Fact Enrichment"],
  ["phase1.spec_generation", "Spec Generation"],
];

const PHASE2_FUNCTIONS: Array<[string, string]> = [
  ["phase2.source_exploration", "Source Exploration"],
  ["phase2.driver_synthesis", "Driver Synthesis"],
  ["phase2.stub_synthesis", "Stub Synthesis"],
  ["phase2.assertion_instantiation", "Assertion Instantiation"],
  ["phase2.compile_diagnose", "Compile & Diagnose"],
  ["phase2.klee_execution", "KLEE Execution"],
  ["phase2.harness_refinement", "Harness Refinement"],
  ["phase2.llm_generation", "LLM Generation"],
];

const PHASE3_FUNCTIONS: Array<[string, string]> = [
  ["phase3.replay_driver_gen", "Replay Driver Generation"],
  ["phase3.asan_compilation", "ASan Compilation"],
  ["phase3.concrete_execution", "Concrete Execution"],
  ["phase3.result_classification", "Result Classification"],
];

interface Props {
  runId: string;
}

export function PipelineControlsSidebar({ runId }: Props) {
  const [open, setOpen] = useState(false);

  const { data: autoConfig } = useQuery({
    queryKey: ["auto-config", runId],
    queryFn: () => getAutoConfig(runId),
  });

  async function resetAll() {
    const all = [
      ...PHASE1_FUNCTIONS,
      ...PHASE2_FUNCTIONS,
      ...PHASE3_FUNCTIONS,
    ].reduce<Record<string, boolean>>((acc, [key]) => {
      acc[key] = true;
      return acc;
    }, {});
    await patchAutoConfig(runId, all);
  }

  if (!autoConfig) return null;

  return (
    <div className="fixed right-0 top-1/2 -translate-y-1/2 z-30">
      {/* Toggle tab */}
      <button
        onClick={() => setOpen(!open)}
        className="absolute right-0 -translate-x-full bg-card border border-border rounded-l-lg px-2 py-3 text-xs text-muted-foreground hover:text-foreground transition-colors shadow-lg"
        style={{ right: open ? "256px" : "0px" }}
      >
        {open ? "▶" : "◀"} Controls
      </button>

      {/* Sidebar */}
      <div
        className={`bg-card border-l border-border h-[80vh] w-64 overflow-y-auto shadow-2xl transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <div className="p-3 border-b border-border flex items-center justify-between">
          <span className="text-xs font-semibold text-foreground">Pipeline Controls</span>
          <button
            onClick={() => void resetAll()}
            className="text-xs text-primary hover:underline"
          >
            Reset all to Auto
          </button>
        </div>

        <div className="p-3 space-y-4">
          <PhaseSection label="Phase 1" functions={PHASE1_FUNCTIONS} autoConfig={autoConfig} runId={runId} />
          <PhaseSection label="Phase 2" functions={PHASE2_FUNCTIONS} autoConfig={autoConfig} runId={runId} />
          <PhaseSection label="Phase 3" functions={PHASE3_FUNCTIONS} autoConfig={autoConfig} runId={runId} />
        </div>
      </div>
    </div>
  );
}

function PhaseSection({
  label,
  functions,
  autoConfig,
  runId,
}: {
  label: string;
  functions: Array<[string, string]>;
  autoConfig: Record<string, boolean>;
  runId: string;
}) {
  return (
    <div>
      <p className="text-xs text-muted-foreground font-semibold uppercase tracking-wider mb-1.5">
        {label}
      </p>
      <div className="space-y-1.5">
        {functions.map(([key, displayLabel]) => (
          <AutoCheckbox
            key={key}
            functionName={key}
            runId={runId}
            defaultChecked={autoConfig[key] !== false}
            label={displayLabel}
          />
        ))}
      </div>
    </div>
  );
}
