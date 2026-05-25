import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getWorkers } from "@/api/settings";
import { useSSE } from "@/hooks/useSSE";
import type { WorkerInfo } from "@/lib/types";
import { cn } from "@/lib/cn";

export function WorkerView() {
  const { run_id } = useParams<{ run_id: string }>();
  const navigate = useNavigate();

  useSSE({
    topics: run_id ? [`runs.${run_id}.workers`] : [],
    enabled: !!run_id,
  });

  const { data: stats, isLoading } = useQuery({
    queryKey: ["workers", run_id],
    queryFn: () => getWorkers(run_id!),
    enabled: !!run_id,
    refetchInterval: 5_000,
  });

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-2 mb-4 text-xs text-muted-foreground">
        <button onClick={() => navigate(`/runs/${run_id}`)} className="hover:text-foreground">
          Run
        </button>
        <span>/</span>
        <span className="text-foreground">Workers</span>
      </div>

      {isLoading && <div className="h-32 bg-card border border-border rounded-lg animate-pulse" />}

      {stats && (
        <>
          <div className="grid grid-cols-4 gap-4 mb-4">
            <StatCard label="Total" value={stats.total} />
            <StatCard label="Active" value={stats.active} color="text-green-300" />
            <StatCard label="Idle" value={stats.idle} color="text-muted-foreground" />
            <StatCard label="Failed" value={stats.failed} color="text-red-300" />
          </div>

          <div className="bg-card border border-border rounded-lg p-4 mb-4">
            <p className="text-xs text-muted-foreground mb-2">Worker grid</p>
            <div className="flex flex-wrap gap-1">
              {(stats.workers ?? []).map((w: WorkerInfo) => (
                <WorkerCell key={w.id} worker={w} />
              ))}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <StatCard label="Specs/min" value={stats.specs_per_min.toFixed(1)} />
            <StatCard label="Avg duration" value={`${stats.avg_spec_duration_min.toFixed(2)} min`} />
            <StatCard label="p95 duration" value={`${stats.p95_spec_duration_min.toFixed(2)} min`} />
            <StatCard label="Tokens/min" value={`${(stats.tokens_per_min / 1000).toFixed(0)}K`} />
            <StatCard label="KLEE-sec/min" value={stats.klee_seconds_per_min.toFixed(0)} />
            <StatCard label="Queue depth" value={stats.queue_depth} />
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  color = "text-foreground",
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="bg-card border border-border rounded-lg p-3">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={cn("text-lg font-bold", color)}>{value}</p>
    </div>
  );
}

function WorkerCell({ worker }: { worker: WorkerInfo }) {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div className="relative">
      <div
        className={cn(
          "w-4 h-4 rounded-sm cursor-pointer",
          worker.status === "active" ? "bg-green-500" :
          worker.status === "idle" ? "bg-gray-500" :
          "bg-red-500"
        )}
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
      />
      {showTooltip && (
        <div className="absolute left-6 top-0 z-10 bg-popover border border-border rounded p-2 text-xs whitespace-nowrap shadow-xl">
          <p className="text-foreground font-semibold">{worker.hostname}</p>
          <p className="text-muted-foreground">Status: {worker.status}</p>
          {worker.current_spec_id && (
            <p className="text-muted-foreground">Spec: {worker.current_spec_id.slice(-6)}</p>
          )}
          {worker.current_turn !== null && (
            <p className="text-muted-foreground">Turn: {worker.current_turn}</p>
          )}
        </div>
      )}
    </div>
  );
}
