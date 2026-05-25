import { useEffect, useRef } from "react";
import { useRunStore } from "./useRunStore";
import { useSpecStore } from "./useSpecStore";
import type { Run, Spec } from "@/lib/types";

interface InterruptCreatedEvent {
  kind: "interrupt_created";
  interrupt_id: string;
  run_id: string;
  spec_id: string | null;
  function_name: string;
}

export type InterruptNotification = InterruptCreatedEvent;

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? "";

interface SSEOptions {
  topics: string[];
  enabled?: boolean;
  onInterrupt?: (event: InterruptNotification) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
}

export function useSSE({ topics, enabled = true, onInterrupt, onConnect, onDisconnect }: SSEOptions) {
  const esRef = useRef<EventSource | null>(null);
  const lastSeqRef = useRef<number>(0);
  const backoffRef = useRef<number>(1000);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const scheduleReconnectRef = useRef<() => void>(() => { /* placeholder */ });

  // Keep callbacks in refs so they never become stale closure deps
  const onInterruptRef = useRef(onInterrupt);
  onInterruptRef.current = onInterrupt;
  const onConnectRef = useRef(onConnect);
  onConnectRef.current = onConnect;
  const onDisconnectRef = useRef(onDisconnect);
  onDisconnectRef.current = onDisconnect;

  // Zustand action methods are stable references — safe to close over
  const applyRunDiff = useRunStore((s) => s.applyDiff);
  const setRun = useRunStore((s) => s.setRun);
  const setSpec = useSpecStore((s) => s.setSpec);

  // Stable key: only reconnect when the topic set or enabled flag actually changes
  const topicsKey = topics.join(",");

  useEffect(() => {
    if (!enabled || !topicsKey) return;

    const connect = () => {
      const token = localStorage.getItem("access_token");
      const params = new URLSearchParams({ topics: topicsKey });
      if (token) params.set("token", token);
      if (lastSeqRef.current > 0) params.set("Last-Event-ID", String(lastSeqRef.current));

      const es = new EventSource(`${BASE_URL}/api/events?${params.toString()}`);
      esRef.current = es;

      es.onopen = () => {
        backoffRef.current = 1000;
        onConnectRef.current?.();
      };

      // Backend sends: data: [{topic, sequence, kind, payload}, ...]
      // One plain data: line (no event: prefix) containing a JSON array of batched events.
      es.onmessage = (event: MessageEvent) => {
        try {
          const items = JSON.parse(event.data as string) as Array<{
            topic: string;
            sequence: number;
            kind: string;
            payload: unknown;
          }>;
          for (const item of items) {
            if (item.sequence > lastSeqRef.current) {
              lastSeqRef.current = item.sequence;
            }
            if (item.kind === "run_update") {
              setRun(item.payload as Run);
            } else if (item.kind === "spec_update") {
              setSpec(item.payload as Spec);
            } else if (item.kind === "counter_diff") {
              const cp = item.payload as { counters: Run["counters"] };
              const runId = item.topic.replace(/^runs\./, "").split(".")[0];
              applyRunDiff(runId, { counters: cp.counters });
            } else if (item.kind === "interrupt_created") {
              onInterruptRef.current?.(item.payload as InterruptCreatedEvent);
            } else if (item.kind === "resync_required") {
              lastSeqRef.current = 0;
              es.close();
              esRef.current = null;
              onDisconnectRef.current?.();
              scheduleReconnectRef.current();
              return;
            }
          }
        } catch { /* ignore parse errors */ }
      };

      es.onerror = () => {
        es.close();
        esRef.current = null;
        onDisconnectRef.current?.();
        scheduleReconnectRef.current();
      };
    };

    scheduleReconnectRef.current = () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        backoffRef.current = Math.min(backoffRef.current * 2, 30_000);
        connect();
      }, backoffRef.current);
    };

    connect();

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      esRef.current?.close();
      esRef.current = null;
    };
  // Re-subscribe only when the topic set or enabled flag changes, not on every render
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, topicsKey]);
}
