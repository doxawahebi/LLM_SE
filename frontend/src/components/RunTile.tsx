import { useNavigate } from "react-router-dom";
import type { Run } from "@/lib/types";
import { StatusBadge } from "./StatusBadge";
import { ProgressBar } from "./ProgressBar";
import { formatRelative } from "@/lib/formatters";
import { pauseRun, resumeRun, cancelRun } from "@/api/runs";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/lib/cn";

interface Props {
  run: Run;
}

export function RunTile({ run }: Props) {
  const navigate = useNavigate();
  const can = useAuth((s) => s.can);

  const p2Total = run.counters.specs_total;
  const p2Done = run.counters.specs_phase2_bug_triggered
    + run.counters.specs_phase2_inconclusive
    + run.counters.specs_phase2_likely_fp
    + run.counters.specs_phase2_errored;
  const p3Total = run.counters.specs_phase2_bug_triggered;
  const p3Done = run.counters.specs_phase3_confirmed;

  const p2Pct = p2Total > 0 ? (p2Done / p2Total) * 100 : 0;
  const p3Pct = p3Total > 0 ? (p3Done / p3Total) * 100 : 0;

  return (
    <div
      className={cn(
        "bg-card border border-border rounded-lg p-4 cursor-pointer hover:border-primary/50 transition-colors"
      )}
      onClick={() => navigate(`/runs/${run.id}`)}
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold text-foreground">{run.name}</h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Started {formatRelative(run.created_at)}
          </p>
        </div>
        <StatusBadge type="run" value={run.status} />
      </div>

      <div className="space-y-2">
        <ProgressBar
          label="Phase 1"
          value={run.counters.specs_emitted > 0 ? 100 : 0}
          color="bg-purple-500"
          showPercent={false}
        />
        <div>
          <ProgressBar
            label="Phase 2"
            value={p2Pct}
            color="bg-blue-500"
            showPercent
          />
          <div className="flex gap-3 mt-1 ml-20 text-xs text-muted-foreground">
            <span className="text-orange-300">triggered: {run.counters.specs_phase2_bug_triggered}</span>
            <span>inconclusive: {run.counters.specs_phase2_inconclusive}</span>
            <span>FP: {run.counters.specs_phase2_likely_fp}</span>
          </div>
        </div>
        <ProgressBar
          label="Phase 3"
          value={p3Pct}
          color="bg-green-500"
          showPercent
        />
      </div>

      <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
        <div className="text-xs text-muted-foreground">
          {run.counters.specs_phase3_confirmed} confirmed · {run.counters.total_llm_tokens.toLocaleString()} tokens
        </div>
        <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
          <button
            className="text-xs px-2 py-1 rounded bg-secondary hover:bg-accent transition-colors"
            onClick={() => navigate(`/runs/${run.id}`)}
          >
            View
          </button>
          {can("cancel_run") && run.status === "running" && (
            <button
              className="text-xs px-2 py-1 rounded bg-secondary hover:bg-accent transition-colors"
              onClick={() => pauseRun(run.id)}
            >
              Pause
            </button>
          )}
          {can("cancel_run") && run.status === "paused" && (
            <button
              className="text-xs px-2 py-1 rounded bg-secondary hover:bg-accent transition-colors"
              onClick={() => resumeRun(run.id)}
            >
              Resume
            </button>
          )}
          {can("cancel_run") && ["running", "paused", "queued"].includes(run.status) && (
            <button
              className="text-xs px-2 py-1 rounded bg-destructive/20 text-destructive hover:bg-destructive/30 transition-colors"
              onClick={() => cancelRun(run.id)}
            >
              Cancel
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
