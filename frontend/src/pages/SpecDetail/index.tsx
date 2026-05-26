import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getSpec } from "@/api/specs";
import { useSSE } from "@/hooks/useSSE";
import { useSpecStore } from "@/hooks/useSpecStore";
import { useInterruptStore } from "@/hooks/useInterruptStore";
import { listInterrupts, type InterruptPoint } from "@/api/client";
import { SpecHeader } from "./SpecHeader";
import { Timeline } from "./Timeline";
import { ArtifactTree } from "./ArtifactTree";
import { InterventionPanel } from "./InterventionPanel";
import { InterruptPanel } from "@/components/interrupt/InterruptPanel";

export function SpecDetail() {
  const { run_id, spec_id } = useParams<{ run_id: string; spec_id: string }>();
  const navigate = useNavigate();

  const setSpec = useSpecStore((s) => s.setSpec);
  const spec = useSpecStore((s) => s.specs.get(spec_id ?? ""));
  const [activeInterrupt, setActiveInterrupt] = useState<InterruptPoint | null>(null);

  const { data: interrupts, refetch: refetchInterrupts } = useQuery({
    queryKey: ["interrupts", run_id],
    queryFn: () => listInterrupts(run_id!),
    enabled: !!run_id,
    select: (data: InterruptPoint[]) =>
      data.filter((i: InterruptPoint) => i.spec_id === spec_id && i.status === "waiting"),
  });

  // Refetch when a new interrupt for this spec appears in the store
  const storeInterrupts = useInterruptStore((s) => s.interrupts);
  const prevCountRef = useRef(0);
  useEffect(() => {
    const count = Array.from(storeInterrupts.values()).filter(
      (ip) => ip.spec_id === spec_id && ip.status === "waiting"
    ).length;
    if (count !== prevCountRef.current) {
      prevCountRef.current = count;
      void refetchInterrupts();
    }
  }, [storeInterrupts, spec_id, refetchInterrupts]);

  useSSE({
    topics: run_id && spec_id
      ? [`runs.${run_id}.specs.${spec_id}`]
      : [],
    enabled: !!(run_id && spec_id),
  });

  useQuery({
    queryKey: ["spec", run_id, spec_id],
    queryFn: async () => {
      if (!run_id || !spec_id) return null;
      const s = await getSpec(run_id, spec_id);
      setSpec(s);
      return s;
    },
    enabled: !!(run_id && spec_id),
  });

  if (!spec) {
    return (
      <div className="p-6">
        <div className="h-32 bg-card border border-border rounded-lg animate-pulse" />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="flex items-center gap-2 mb-4 text-xs text-muted-foreground">
        <button onClick={() => navigate("/")} className="hover:text-foreground">
          Runs
        </button>
        <span>/</span>
        <button onClick={() => navigate(`/runs/${run_id}`)} className="hover:text-foreground">
          {run_id?.slice(-6)}
        </button>
        <span>/</span>
        <span className="text-foreground">{spec.func}</span>
      </div>

      <SpecHeader spec={spec} />

      {/* Waiting interrupt banner */}
      {interrupts && interrupts.length > 0 && (
        <div className="mb-4 bg-yellow-900/20 border border-yellow-700/40 rounded-lg p-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-yellow-300">⏸</span>
            <span className="text-sm text-yellow-200">
              Pipeline paused at: <strong>{interrupts[0].function_name}</strong>
            </span>
          </div>
          <button
            onClick={() => setActiveInterrupt(interrupts[0])}
            className="px-3 py-1.5 text-xs bg-yellow-700/40 text-yellow-200 hover:bg-yellow-700/60 rounded transition-colors"
          >
            Open Interrupt Panel
          </button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        {/* Timeline (left) */}
        <div className="bg-card border border-border rounded-lg p-4">
          <p className="text-xs font-semibold text-muted-foreground mb-3 uppercase tracking-wider">
            Timeline
          </p>
          <Timeline
            runId={run_id ?? ""}
            specId={spec_id ?? ""}
            phase3Confirmed={spec.phase3_status === "confirmed"}
          />
        </div>

        {/* Right column: Artifacts + Intervention */}
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-lg p-4">
            <p className="text-xs font-semibold text-muted-foreground mb-3 uppercase tracking-wider">
              Artifacts
            </p>
            <ArtifactTree runId={run_id ?? ""} specId={spec_id ?? ""} />
          </div>

          <InterventionPanel spec={spec} runId={run_id ?? ""} />
        </div>
      </div>

      {/* Interrupt panel overlay */}
      {activeInterrupt && (
        <InterruptPanel
          interrupt={activeInterrupt}
          runId={run_id ?? ""}
          onClose={() => {
            setActiveInterrupt(null);
            void refetchInterrupts();
          }}
        />
      )}
    </div>
  );
}
