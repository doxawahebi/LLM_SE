import { useNavigate } from "react-router-dom";
import type { Run } from "@/lib/types";
import { StatusBadge } from "@/components/StatusBadge";
import { ProgressBar } from "@/components/ProgressBar";
import { formatRelative } from "@/lib/formatters";
import { pauseRun, resumeRun, cancelRun, rerunFailed } from "@/api/runs";
import { useAuth } from "@/hooks/useAuth";

interface Props { run: Run }

export function RunHeader({ run }: Props) {
  const navigate = useNavigate();
  const can = useAuth((s) => s.can);

  const p1Pct = run.counters.specs_emitted > 0 ? 100 : 0;
  const p2Done = run.counters.specs_phase2_bug_triggered
    + run.counters.specs_phase2_inconclusive
    + run.counters.specs_phase2_likely_fp
    + run.counters.specs_phase2_errored;
  const p2Pct = run.counters.specs_total > 0
    ? (p2Done / run.counters.specs_total) * 100
    : 0;
  const p3Pct = run.counters.specs_phase2_bug_triggered > 0
    ? (run.counters.specs_phase3_confirmed / run.counters.specs_phase2_bug_triggered) * 100
    : 0;

  return (
    <div className="bg-card border border-border rounded-lg p-5 mb-4">
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-base font-bold text-foreground">{run.name}</h1>
            <StatusBadge type="run" value={run.status} />
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Started {formatRelative(run.created_at)} ·{" "}
            {run.counters.specs_total.toLocaleString()} specs ·{" "}
            {run.counters.total_llm_tokens.toLocaleString()} tokens
          </p>
        </div>

        <div className="flex gap-2">
          {can("start_run") && (
            <button
              onClick={() => navigate(`/runs/new?clone=${run.id}`)}
              className="px-3 py-1.5 text-xs bg-secondary hover:bg-accent rounded transition-colors"
            >
              Clone
            </button>
          )}
          {can("cancel_run") && run.status === "running" && (
            <button
              onClick={() => void pauseRun(run.id)}
              className="px-3 py-1.5 text-xs bg-secondary hover:bg-accent rounded transition-colors"
            >
              Pause
            </button>
          )}
          {can("cancel_run") && run.status === "paused" && (
            <button
              onClick={() => void resumeRun(run.id)}
              className="px-3 py-1.5 text-xs bg-primary text-primary-foreground hover:bg-primary/80 rounded transition-colors"
            >
              Resume
            </button>
          )}
          {can("cancel_run") && ["running", "paused"].includes(run.status) && (
            <button
              onClick={() => void rerunFailed(run.id)}
              className="px-3 py-1.5 text-xs bg-secondary hover:bg-accent rounded transition-colors"
            >
              Re-run failed
            </button>
          )}
          {can("cancel_run") && ["running", "paused", "queued"].includes(run.status) && (
            <button
              onClick={() => void cancelRun(run.id)}
              className="px-3 py-1.5 text-xs bg-destructive/20 text-destructive hover:bg-destructive/30 rounded transition-colors"
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      <div className="space-y-2">
        <ProgressBar
          label="Phase 1"
          value={p1Pct}
          color="bg-purple-500"
          showPercent
        />
        <div>
          <ProgressBar label="Phase 2" value={p2Pct} color="bg-blue-500" showPercent />
          <div className="flex gap-4 mt-1 ml-20 text-xs text-muted-foreground">
            <span className="text-orange-300">triggered: {run.counters.specs_phase2_bug_triggered}</span>
            <span>inconclusive: {run.counters.specs_phase2_inconclusive}</span>
            <span>FP: {run.counters.specs_phase2_likely_fp}</span>
            <span className="text-red-400">errors: {run.counters.specs_phase2_errored}</span>
          </div>
        </div>
        <ProgressBar
          label="Phase 3"
          value={p3Pct}
          color="bg-green-500"
          showPercent
        />
      </div>
    </div>
  );
}
