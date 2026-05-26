import { useEffect, useLayoutEffect, useRef } from "react";
import type { SSEMessage, SSEBatch } from "@/shared/contracts/sailor.types";
import { useRunStore } from "./useRunStore";
import { useSpecStore } from "./useSpecStore";
import { useInterruptStore } from "./useInterruptStore";
import { showWarning } from "@/lib/toast";
import type { Spec, RunStatus, RunCounters } from "@/lib/types";

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? "";

export interface SSEOptions {
  topics: string[];
  enabled?: boolean;
  onConnect?: () => void;
  onDisconnect?: () => void;
}

function isBatch(data: unknown): data is SSEBatch {
  return (
    typeof data === "object" &&
    data !== null &&
    "batch" in data &&
    Array.isArray((data as SSEBatch).batch)
  );
}

function isMessage(data: unknown): data is SSEMessage {
  return (
    typeof data === "object" &&
    data !== null &&
    "kind" in data &&
    !("batch" in data)
  );
}

export function useSSE({ topics, enabled = true, onConnect, onDisconnect }: SSEOptions) {
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);

  // Update refs synchronously so the effect closure sees fresh callbacks
  useLayoutEffect(() => {
    onConnectRef.current = onConnect;
    onDisconnectRef.current = onDisconnect;
  });

  const topicsKey = topics.join(",");

  const setRun = useRunStore((s) => s.setRun);
  const setStatus = useRunStore((s) => s.setStatus);
  const setCounters = useRunStore((s) => s.setCounters);
  const setAutoConfig = useRunStore((s) => s.setAutoConfig);
  const upsertSpec = useSpecStore((s) => s.upsert);
  const clearForRun = useSpecStore((s) => s.clearForRun);
  const upsertInterrupt = useInterruptStore((s) => s.upsert);
  const markResolved = useInterruptStore((s) => s.markResolved);

  useEffect(() => {
    if (!enabled || !topicsKey) return;

    const token = localStorage.getItem("access_token");
    const params = new URLSearchParams({ topics: topicsKey });
    if (token) params.set("token", token);

    const es = new EventSource(`${BASE_URL}/api/events?${params.toString()}`);

    es.onopen = () => {
      onConnectRef.current?.();
    };

    es.onerror = () => {
      onDisconnectRef.current?.();
      // Browser auto-reconnects via Last-Event-ID — do not interfere
    };

    const dispatch = (m: SSEMessage) => {
      switch (m.kind) {
        case "run_status_changed":
          setStatus(m.payload.run_id, m.payload.status as RunStatus);
          return;

        case "run_counters_updated":
          setCounters(m.payload.run_id, m.payload.counters as unknown as RunCounters);
          return;

        case "spec_state_changed":
          // Full snapshot — replace local copy entirely (sse_contract §5.3)
          upsertSpec(m.payload.spec as unknown as Spec);
          return;

        case "spec_intervention_applied":
          showWarning(`Intervention applied to spec ${m.payload.spec_id}`);
          return;

        case "turn_appended":
          // Timeline is page-local; handled by SpecDetail directly
          return;

        case "worker_heartbeat":
          // Worker view handles this locally
          return;

        case "log_line":
          // Logs view subscribes to its own topic
          return;

        case "resync_required": {
          const runId = m.topic.replace(/^runs\./, "").split(".")[0];
          clearForRun(runId);
          return;
        }

        case "interrupt_created":
          upsertInterrupt(m.payload.interrupt);
          return;

        case "interrupt_resolved":
          markResolved(m.payload.interrupt_id, m.payload.resolution);
          return;

        case "auto_config_changed":
          setAutoConfig(m.payload.run_id, m.payload.auto_config);
          return;

        default: {
          // Exhaustive type check — TypeScript errors here if a new kind is unhandled.
          const _exhaustive: never = m;
          void _exhaustive;
        }
      }
    };

    const handleFrame = (event: MessageEvent) => {
      try {
        const data: unknown = JSON.parse(event.data as string);
        if (isBatch(data)) {
          for (const msg of data.batch) dispatch(msg);
        } else if (isMessage(data)) {
          dispatch(data);
        }
      } catch {
        // ignore parse errors
      }
    };

    es.onmessage = handleFrame;

    // Named-event handlers for SSE `event:` field routing
    const kinds: SSEMessage["kind"][] = [
      "run_status_changed", "run_counters_updated", "spec_state_changed",
      "spec_intervention_applied", "turn_appended", "worker_heartbeat",
      "log_line", "resync_required", "interrupt_created", "interrupt_resolved",
      "auto_config_changed",
    ];
    for (const kind of kinds) {
      es.addEventListener(kind, handleFrame as EventListener);
    }
    es.addEventListener("batch", handleFrame as EventListener);

    // setRun is available for pages that do a full fetch + store.setRun(data)
    void setRun;

    return () => {
      es.close();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, topicsKey]);
}
