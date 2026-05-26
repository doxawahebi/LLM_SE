import { create } from "zustand";
import type { Run, RunStatus, RunCounters } from "@/lib/types";
import type { AutoConfig } from "@/shared/contracts/sailor.types";

interface RunStore {
  runs: Map<string, Run>;
  autoConfigs: Map<string, AutoConfig>;

  // Full-replace (from API fetches)
  setRun: (run: Run) => void;
  setRuns: (runs: Run[]) => void;

  // Partial SSE updates (snapshot semantics per sse_contract §5.3)
  setStatus: (run_id: string, status: RunStatus) => void;
  setCounters: (run_id: string, counters: RunCounters) => void;
  setAutoConfig: (run_id: string, config: AutoConfig) => void;

  removeRun: (id: string) => void;
}

export const useRunStore = create<RunStore>((set) => ({
  runs: new Map(),
  autoConfigs: new Map(),

  setRun: (run) =>
    set((s) => {
      const next = new Map(s.runs);
      next.set(run.id, run);
      return { runs: next };
    }),

  setRuns: (runs) =>
    set(() => ({
      runs: new Map(runs.map((r) => [r.id, r])),
    })),

  setStatus: (run_id, status) =>
    set((s) => {
      // run_id may be the `id` field from old Run type; try both lookups
      const existing = s.runs.get(run_id);
      if (!existing) return {};
      const next = new Map(s.runs);
      next.set(run_id, { ...existing, status });
      return { runs: next };
    }),

  setCounters: (run_id, counters) =>
    set((s) => {
      const existing = s.runs.get(run_id);
      if (!existing) return {};
      const next = new Map(s.runs);
      next.set(run_id, { ...existing, counters });
      return { runs: next };
    }),

  setAutoConfig: (run_id, config) =>
    set((s) => {
      const next = new Map(s.autoConfigs);
      next.set(run_id, config);
      return { autoConfigs: next };
    }),

  removeRun: (id) =>
    set((s) => {
      const next = new Map(s.runs);
      next.delete(id);
      return { runs: next };
    }),
}));
