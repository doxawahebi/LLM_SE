import { useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useSSE } from "@/hooks/useSSE";
import { useInterruptStore } from "@/hooks/useInterruptStore";
import { getInterrupt } from "@/api/client";
import { InterruptPanel } from "@/components/interrupt/InterruptPanel";
import type { InterruptPoint as SharedInterruptPoint } from "@/shared/contracts/sailor.types";
import type { InterruptPoint } from "@/api/client";

export function InterruptDetail() {
  const { run_id, interrupt_id } = useParams<{
    run_id: string;
    interrupt_id: string;
  }>();

  const upsert = useInterruptStore((s) => s.upsert);
  const interrupt = useInterruptStore((s) =>
    interrupt_id ? s.interrupts.get(interrupt_id) : undefined
  );

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["interrupt", run_id, interrupt_id],
    queryFn: () => getInterrupt(run_id!, interrupt_id!),
    enabled: !!(run_id && interrupt_id),
  });

  useEffect(() => {
    if (data) upsert(data as unknown as SharedInterruptPoint);
  }, [data, upsert]);

  useSSE({
    topics: run_id ? [`runs.${run_id}`] : [],
    enabled: !!(run_id && interrupt_id),
    onDisconnect: () => { void refetch(); },
  });

  if (isLoading && !interrupt) {
    return <div className="p-6 text-zinc-400">Loading interrupt…</div>;
  }

  if (isError && !interrupt) {
    return <div className="p-6 text-red-400">Failed to load interrupt.</div>;
  }

  const ip = (interrupt as unknown as InterruptPoint | undefined) ?? data;

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="flex items-center gap-4 mb-6">
        <Link
          to={`/runs/${run_id}/interrupts`}
          className="text-zinc-400 hover:text-zinc-100 text-sm"
        >
          ← All Interrupts
        </Link>
      </div>

      {ip ? (
        <InterruptPanel
          interrupt={ip}
          runId={run_id!}
          onClose={() => { void refetch(); }}
        />
      ) : null}
    </div>
  );
}
