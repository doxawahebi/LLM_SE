import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { listRuns, getDashboardMetrics } from "@/api/runs";
import { RunTile } from "@/components/RunTile";
import { useSSE } from "@/hooks/useSSE";
import { useRunStore } from "@/hooks/useRunStore";
import { formatTokens } from "@/lib/formatters";
import type { Run } from "@/lib/types";

export function Dashboard() {
  const navigate = useNavigate();
  useSSE({ topics: ["runs.all"] });

  const storeRuns = useRunStore((s) => s.runs);
  const setRuns = useRunStore((s) => s.setRuns);

  const { isLoading, error } = useQuery({
    queryKey: ["runs"],
    queryFn: async () => {
      const runs = await listRuns();
      setRuns(runs);
      return runs;
    },
    refetchInterval: 30_000,
  });

  const { data: metrics } = useQuery({
    queryKey: ["metrics"],
    queryFn: getDashboardMetrics,
    refetchInterval: 60_000,
  });

  const runs = Array.from(storeRuns.values()).sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-lg font-bold text-foreground">Runs</h1>
        <button
          onClick={() => navigate("/runs/new")}
          className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors"
        >
          + New Run
        </button>
      </div>

      {metrics && (
        <div className="grid grid-cols-5 gap-4 mb-6 bg-card border border-border rounded-lg p-4">
          <MetricItem label="Total runs" value={String(metrics.total_runs ?? 0)} />
          <MetricItem label="Confirmed bugs" value={String(metrics.confirmed_bugs ?? 0)} />
          <MetricItem
            label="Avg tokens/bug"
            value={formatTokens(metrics.avg_tokens_per_bug ?? 0)}
          />
          <MetricItem
            label="Avg P2 latency"
            value={metrics.avg_phase2_latency_min != null
              ? `${metrics.avg_phase2_latency_min.toFixed(1)} min`
              : "—"}
          />
          <MetricItem
            label="Worker util"
            value={metrics.worker_utilization != null
              ? `${Math.round(metrics.worker_utilization * 100)}%`
              : "—"}
          />
        </div>
      )}

      {isLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-48 bg-card border border-border rounded-lg animate-pulse" />
          ))}
        </div>
      )}

      {error && (
        <div className="text-red-400 text-sm p-4 bg-destructive/10 rounded border border-destructive/30">
          Failed to load runs
        </div>
      )}

      {!isLoading && runs.length === 0 && (
        <div className="text-center py-16 text-muted-foreground">
          <p className="text-sm">No runs yet.</p>
          <button
            onClick={() => navigate("/runs/new")}
            className="mt-4 px-4 py-2 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors"
          >
            Start your first run
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {runs.map((run: Run) => (
          <RunTile key={run.id} run={run} />
        ))}
      </div>
    </div>
  );
}

function MetricItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-semibold text-foreground">{value}</p>
    </div>
  );
}
