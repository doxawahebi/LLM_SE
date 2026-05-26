import { useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useSSE } from "@/hooks/useSSE";
import { useInterruptStore } from "@/hooks/useInterruptStore";
import { listInterrupts } from "@/api/client";
import { pipelineLabels } from "@/lib/pipelineLabels";
import type { InterruptPoint } from "@/shared/contracts/sailor.types";
import type { PipelineFunctionId } from "@/shared/contracts/sailor.types";

export function InterruptList() {
  const { run_id } = useParams<{ run_id: string }>();
  const navigate = useNavigate();
  const upsert = useInterruptStore((s) => s.upsert);
  const interrupts = useInterruptStore((s) => s.interrupts);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["interrupts", run_id, "waiting"],
    queryFn: () => listInterrupts(run_id!),
    enabled: !!run_id,
  });

  useEffect(() => {
    if (data) {
      for (const ip of data) upsert(ip as unknown as InterruptPoint);
    }
  }, [data, upsert]);

  useSSE({
    topics: run_id ? [`runs.${run_id}`] : [],
    enabled: !!run_id,
    onDisconnect: () => { void refetch(); },
  });

  const waitingList = Array.from(interrupts.values()).filter(
    (ip) => ip.run_id === run_id && ip.status === "waiting"
  );

  if (isLoading) {
    return (
      <div className="p-6 text-zinc-400">Loading interrupts…</div>
    );
  }

  if (isError) {
    return (
      <div className="p-6 text-red-400">Failed to load interrupts.</div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="flex items-center gap-4 mb-6">
        <Link
          to={`/runs/${run_id}`}
          className="text-zinc-400 hover:text-zinc-100 text-sm"
        >
          ← Back to Run
        </Link>
        <h1 className="text-xl font-semibold text-zinc-100">
          Waiting Interrupts
          {waitingList.length > 0 && (
            <span className="ml-2 px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 text-sm">
              {waitingList.length}
            </span>
          )}
        </h1>
      </div>

      {waitingList.length === 0 ? (
        <div className="text-zinc-400 text-center py-12">
          No waiting interrupts. The pipeline is running automatically.
        </div>
      ) : (
        <ul className="flex flex-col gap-3">
          {waitingList.map((ip) => (
            <li key={ip.interrupt_id}>
              <button
                onClick={() =>
                  navigate(`/runs/${run_id}/interrupts/${ip.interrupt_id}`)
                }
                className="w-full text-left p-4 rounded-lg border border-zinc-700 bg-zinc-900 hover:border-amber-500/50 hover:bg-zinc-800 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-amber-400 font-medium">
                      ⏸ {pipelineLabels[ip.function_name as PipelineFunctionId] ?? ip.function_name}
                    </span>
                    {ip.spec_id && (
                      <span className="ml-2 text-zinc-400 text-sm">
                        spec {ip.spec_id}
                      </span>
                    )}
                  </div>
                  <div className="text-zinc-500 text-sm">
                    {new Date(ip.created_at).toLocaleTimeString()}
                  </div>
                </div>
                <div className="mt-1 text-zinc-500 text-sm">
                  Scope: {ip.scope}
                  {ip.turn !== null && ip.turn !== undefined && ` · Turn ${ip.turn}`}
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
