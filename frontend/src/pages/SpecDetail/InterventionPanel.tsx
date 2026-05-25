import { useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { cpp } from "@codemirror/lang-cpp";
import { json } from "@codemirror/lang-json";
import { oneDark } from "@codemirror/theme-one-dark";
import { intervene } from "@/api/specs";
import { ConfirmModal } from "@/components/ConfirmModal";
import type { Spec } from "@/lib/types";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/lib/cn";

type Mode = "A" | "B" | "C";

interface Props {
  spec: Spec;
  runId: string;
}

export function InterventionPanel({ spec, runId }: Props) {
  const [mode, setMode] = useState<Mode>("A");
  const [modeAFile, setModeAFile] = useState("driver");
  const [modeAContent, setModeAContent] = useState("");
  const [modeBOutcome, setModeBOutcome] = useState("inconclusive");
  const [modeCSpec, setModeCSpec] = useState(JSON.stringify(spec, null, 2));
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const can = useAuth((s) => s.can);

  if (!can("intervene")) {
    return (
      <div className="p-4 text-xs text-muted-foreground">
        Intervention requires intervener or admin role.
      </div>
    );
  }

  const canIntervene =
    spec.phase2_status === "inconclusive" ||
    spec.phase3_status === "rejected" ||
    spec.error_class !== null;

  if (!canIntervene) {
    return (
      <div className="p-4 text-xs text-muted-foreground">
        Intervention available when spec is paused, errored, or you click "Take control".
      </div>
    );
  }

  async function apply() {
    setLoading(true);
    setError("");
    try {
      if (mode === "A") {
        await intervene(runId, spec.id, {
          mode: "edit_harness",
          file: modeAFile,
          content: modeAContent,
        });
      } else if (mode === "B") {
        await intervene(runId, spec.id, {
          mode: "force_outcome",
          outcome: modeBOutcome,
        });
      } else {
        await intervene(runId, spec.id, {
          mode: "edit_spec",
          spec_json: modeCSpec,
        });
      }
    } catch (e) {
      setError((e as { message?: string }).message ?? "Intervention failed");
    } finally {
      setLoading(false);
      setConfirmOpen(false);
    }
  }

  const turnsRemaining =
    (spec.phase2_status ? 60 : 0) - (spec.current_turn ?? 0);

  const modes: { key: Mode; label: string }[] = [
    { key: "A", label: "Edit harness, resume" },
    { key: "B", label: "Force outcome" },
    { key: "C", label: "Edit spec, re-run" },
  ];

  return (
    <div className="bg-card border border-border rounded-lg">
      <div className="px-4 py-3 border-b border-border">
        <p className="text-xs font-semibold text-foreground mb-2">Intervention</p>
        <div className="flex gap-1">
          {modes.map((m) => (
            <button
              key={m.key}
              onClick={() => setMode(m.key)}
              className={cn(
                "px-3 py-1.5 text-xs rounded transition-colors",
                mode === m.key
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary hover:bg-accent"
              )}
            >
              {m.label}
            </button>
          ))}
        </div>
      </div>

      <div className="p-4">
        {mode === "A" && (
          <div className="space-y-3">
            <p className="text-xs text-yellow-300">
              ⚠ Editing will consume 1 of your remaining {turnsRemaining} turns.
            </p>
            <div className="flex gap-2">
              {["driver", "slice", "assertions"].map((f) => (
                <button
                  key={f}
                  onClick={() => setModeAFile(f)}
                  className={cn(
                    "px-2 py-1 text-xs rounded",
                    modeAFile === f ? "bg-primary text-primary-foreground" : "bg-secondary"
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
            <div className="h-48 overflow-hidden rounded border border-border">
              <CodeMirror
                value={modeAContent}
                onChange={setModeAContent}
                extensions={[cpp()]}
                theme={oneDark}
                height="192px"
                basicSetup={{ lineNumbers: true }}
              />
            </div>
            <button
              onClick={() => setConfirmOpen(true)}
              disabled={!modeAContent}
              className="px-4 py-2 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors disabled:opacity-50"
            >
              Apply & re-enter loop at compile step
            </button>
          </div>
        )}

        {mode === "B" && (
          <div className="space-y-3">
            <select
              value={modeBOutcome}
              onChange={(e) => setModeBOutcome(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-secondary border border-border rounded text-foreground"
            >
              <option value="inconclusive">Mark inconclusive, do not retry</option>
              <option value="likely_false_positive">Mark likely false positive</option>
              <option value="skip_to_phase3">Skip to Phase 3 with witness</option>
            </select>
            <button
              onClick={() => setConfirmOpen(true)}
              className="px-4 py-2 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors"
            >
              Apply
            </button>
          </div>
        )}

        {mode === "C" && (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Old Phase 2 work will be archived. A fresh loop starts at turn 0.
            </p>
            <div className="h-48 overflow-hidden rounded border border-border">
              <CodeMirror
                value={modeCSpec}
                onChange={setModeCSpec}
                extensions={[json()]}
                theme={oneDark}
                height="192px"
                basicSetup={{ lineNumbers: true }}
              />
            </div>
            <button
              onClick={() => setConfirmOpen(true)}
              className="px-4 py-2 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors"
            >
              Re-run from Phase 2 start
            </button>
          </div>
        )}

        {error && <p className="text-xs text-red-400 mt-2">{error}</p>}
      </div>

      <ConfirmModal
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title="Confirm Intervention"
        description={
          mode === "A"
            ? `This will edit ${modeAFile}.c and re-enter the compile step. 1 turn will be consumed.`
            : mode === "B"
            ? `Force outcome to "${modeBOutcome}". This cannot be undone.`
            : "All existing Phase 2 work will be archived and the loop will restart at turn 0."
        }
        onConfirm={() => void apply()}
        confirmLabel={loading ? "Applying..." : "Confirm"}
      />
    </div>
  );
}
