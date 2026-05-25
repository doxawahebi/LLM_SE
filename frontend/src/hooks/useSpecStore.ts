import { create } from "zustand";
import type { Spec } from "@/lib/types";
import { applyMergePatch } from "@/lib/jsonPatch";

interface SpecStore {
  specs: Map<string, Spec>;
  setSpec: (spec: Spec) => void;
  setSpecs: (specs: Spec[]) => void;
  applyDiff: (id: string, patch: Partial<Spec>) => void;
  clearSpecs: () => void;
}

export const useSpecStore = create<SpecStore>((set) => ({
  specs: new Map(),

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

  applyDiff: (id, patch) =>
    set((s) => {
      const existing = s.specs.get(id);
      if (!existing) return {};
      const next = new Map(s.specs);
      next.set(id, applyMergePatch(existing, patch));
      return { specs: next };
    }),

  clearSpecs: () => set({ specs: new Map() }),
}));
