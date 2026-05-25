import { create } from "zustand";
import type { Run } from "@/lib/types";
import { applyMergePatch } from "@/lib/jsonPatch";

interface RunStore {
  runs: Map<string, Run>;
  setRun: (run: Run) => void;
  setRuns: (runs: Run[]) => void;
  applyDiff: (id: string, patch: Partial<Run>) => void;
  removeRun: (id: string) => void;
}

export const useRunStore = create<RunStore>((set) => ({
  runs: new Map(),

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

  applyDiff: (id, patch) =>
    set((s) => {
      const existing = s.runs.get(id);
      if (!existing) return {};
      const next = new Map(s.runs);
      next.set(id, applyMergePatch(existing, patch));
      return { runs: next };
    }),

  removeRun: (id) =>
    set((s) => {
      const next = new Map(s.runs);
      next.delete(id);
      return { runs: next };
    }),
}));
