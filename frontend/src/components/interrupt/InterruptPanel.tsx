import { useState } from "react";
import { InterruptFileRow } from "./InterruptFileRow";
import { resumeInterrupt, skipInterrupt, patchAutoConfig, type InterruptPoint } from "@/api/client";

// Phase-specific controls
import { DBBuildInterrupt } from "./phase1/DBBuildInterrupt";
import { QuerySelectorInterrupt } from "./phase1/QuerySelectorInterrupt";
import { SARIFParseInterrupt } from "./phase1/SARIFParseInterrupt";
import { FactEnrichInterrupt } from "./phase1/FactEnrichInterrupt";
import { SpecGenInterrupt } from "./phase1/SpecGenInterrupt";
import { SourceExploreInterrupt } from "./phase2/SourceExploreInterrupt";
import { SpecSelectorInterrupt } from "./phase2/SpecSelectorInterrupt";
import { DriverSynthInterrupt } from "./phase2/DriverSynthInterrupt";
import { StubSynthInterrupt } from "./phase2/StubSynthInterrupt";
import { CompileDiagInterrupt } from "./phase2/CompileDiagInterrupt";
import { KLEEExecInterrupt } from "./phase2/KLEEExecInterrupt";
import { ManualHarnessEditor } from "./phase2/ManualHarnessEditor";
import { ReplayDriverInterrupt } from "./phase3/ReplayDriverInterrupt";
import { ASanCompileInterrupt } from "./phase3/ASanCompileInterrupt";
import { ResultClassifyInterrupt } from "./phase3/ResultClassifyInterrupt";

interface Props {
  interrupt: InterruptPoint;
  runId: string;
  onClose: () => void;
}

function FunctionControls({
  functionName,
  interrupt,
  optionOverrides,
  setOptionOverrides,
  modifiedFiles,
}: {
  functionName: string;
  interrupt: InterruptPoint;
  optionOverrides: Record<string, unknown>;
  setOptionOverrides: (v: Record<string, unknown>) => void;
  modifiedFiles: Map<string, string>;
}) {
  const fn = functionName.toLowerCase();

  if (fn.includes("db_build") || fn.includes("codeql_db"))
    return <DBBuildInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("query") || fn.includes("query_exec"))
    return <QuerySelectorInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("sarif"))
    return <SARIFParseInterrupt interrupt={interrupt} />;
  if (fn.includes("fact_enrich") || fn.includes("enrichment"))
    return <FactEnrichInterrupt interrupt={interrupt} />;
  if (fn.includes("spec_gen") || fn.includes("specification"))
    return <SpecGenInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("source_explor") || fn.includes("exploration"))
    return <SourceExploreInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("spec_selector") || fn.includes("spec_selection"))
    return <SpecSelectorInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("driver_synth"))
    return <DriverSynthInterrupt interrupt={interrupt} modifiedFiles={modifiedFiles} />;
  if (fn.includes("stub_synth"))
    return <StubSynthInterrupt interrupt={interrupt} modifiedFiles={modifiedFiles} />;
  if (fn.includes("compile") || fn.includes("diagnos"))
    return <CompileDiagInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("klee") && !fn.includes("replay"))
    return <KLEEExecInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("manual") || fn.includes("llm_disable"))
    return <ManualHarnessEditor interrupt={interrupt} modifiedFiles={modifiedFiles} />;
  if (fn.includes("replay_driver"))
    return <ReplayDriverInterrupt interrupt={interrupt} modifiedFiles={modifiedFiles} />;
  if (fn.includes("asan") || fn.includes("asan_compil"))
    return <ASanCompileInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;
  if (fn.includes("result") || fn.includes("classif"))
    return <ResultClassifyInterrupt interrupt={interrupt} overrides={optionOverrides} setOverrides={setOptionOverrides} />;

  return null;
}

export function InterruptPanel({ interrupt, runId, onClose }: Props) {
  const [modifiedFiles, setModifiedFiles] = useState<Map<string, string>>(new Map());
  const [optionOverrides, setOptionOverrides] = useState<Record<string, unknown>>(
    interrupt.option_overrides ?? {}
  );
  const [reEnableAuto, setReEnableAuto] = useState(false);
  const [loading, setLoading] = useState<"resume" | "skip" | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleModified(name: string, contentBase64: string) {
    setModifiedFiles((prev) => {
      const next = new Map(prev);
      next.set(name, contentBase64);
      return next;
    });
  }

  async function handleResume() {
    setLoading("resume");
    setError(null);
    try {
      const payload = {
        modified_files: Array.from(modifiedFiles.entries()).map(([name, content_base64]) => ({
          name,
          content_base64,
        })),
        option_overrides: optionOverrides,
      };
      await resumeInterrupt(runId, interrupt.interrupt_id, payload);
      if (reEnableAuto) {
        await patchAutoConfig(runId, { [interrupt.function_name]: true });
      }
      onClose();
    } catch (err: unknown) {
      setError((err as { message?: string }).message ?? "Resume failed");
    } finally {
      setLoading(null);
    }
  }

  async function handleSkip() {
    setLoading("skip");
    setError(null);
    try {
      await skipInterrupt(runId, interrupt.interrupt_id);
      onClose();
    } catch (err: unknown) {
      setError((err as { message?: string }).message ?? "Skip failed");
    } finally {
      setLoading(null);
    }
  }

  const phaseLabel =
    interrupt.phase === 1 ? "Phase 1" :
    interrupt.phase === 2 ? "Phase 2" : "Phase 3";

  return (
    <div className="fixed inset-0 z-50 flex items-end md:items-center justify-center bg-black/70 p-4">
      <div className="bg-card border border-border rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-4 py-3 border-b border-border">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-yellow-300">⏸</span>
              <span className="text-sm font-semibold text-foreground">
                Interrupted: {interrupt.function_name}
              </span>
            </div>
            <button
              onClick={onClose}
              className="text-muted-foreground hover:text-foreground"
            >
              ✕
            </button>
          </div>
          <div className="mt-1 flex gap-3 text-xs text-muted-foreground">
            {interrupt.spec_id && <span>Spec: {interrupt.spec_id.slice(-8)}</span>}
            <span>{phaseLabel}</span>
            {interrupt.turn !== null && <span>Turn: {interrupt.turn}</span>}
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Input files */}
          {interrupt.input_files.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Input Files
                </p>
                <span className="text-xs text-muted-foreground">
                  {modifiedFiles.size > 0 && `${modifiedFiles.size} modified`}
                </span>
              </div>
              <div className="space-y-1">
                {interrupt.input_files.map((f) => (
                  <InterruptFileRow
                    key={f.name}
                    file={f}
                    interruptId={interrupt.interrupt_id}
                    onModified={handleModified}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Function-specific controls */}
          <FunctionControls
            functionName={interrupt.function_name}
            interrupt={interrupt}
            optionOverrides={optionOverrides}
            setOptionOverrides={setOptionOverrides}
            modifiedFiles={modifiedFiles}
          />
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-border space-y-2">
          {error && (
            <p className="text-xs text-red-400">{error}</p>
          )}
          <div className="flex items-center justify-between gap-2">
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
              <input
                type="checkbox"
                checked={reEnableAuto}
                onChange={(e) => setReEnableAuto(e.target.checked)}
                className="w-3 h-3"
              />
              ☑ Auto (re-enable for future)
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => void handleSkip()}
                disabled={loading !== null}
                className="px-4 py-2 text-xs bg-secondary hover:bg-accent rounded transition-colors disabled:opacity-50"
              >
                {loading === "skip" ? "Skipping…" : "Skip this function"}
              </button>
              <button
                onClick={() => void handleResume()}
                disabled={loading !== null}
                className="px-4 py-2 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 transition-colors disabled:opacity-50"
              >
                {loading === "resume" ? "Resuming…" : "Resume with current inputs"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
