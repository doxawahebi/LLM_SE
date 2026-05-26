import { create } from "zustand";
import type { Spec } from "@/lib/types";

interface SpecStore {
  specs: Map<string, Spec>;

  // Full-replace (snapshot semantics per sse_contract §5.3)
  upsert: (spec: Spec) => void;
  setSpec: (spec: Spec) => void;  // alias for compat
  setSpecs: (specs: Spec[]) => void;
  clearForRun: (run_id: string) => void;
  clearSpecs: () => void;
}

export const useSpecStore = create<SpecStore>((set) => ({
  specs: new Map(),

  upsert: (spec) =>
    set((s) => {
      const next = new Map(s.specs);
      const key = spec.id;
      next.set(key, spec);
      return { specs: next };
    }),

  setSpec: (spec) =>
    set((s) => {
      const next = new Map(s.specs);
      next.set(spec.id, spec);
      return { specs: next };
    }),

  setSpecs: (specs) =>
    set((s) => {
      const next = new Map(s.specs);
      for (const spec of specs) {
        next.set(spec.id, spec);
      }
      return { specs: next };
    }),

  clearForRun: (run_id) =>
    set((s) => {
      const next = new Map(s.specs);
      for (const [key, spec] of next) {
        if (spec.run_id === run_id) next.delete(key);
      }
      return { specs: next };
    }),

  clearSpecs: () => set({ specs: new Map() }),
}));
