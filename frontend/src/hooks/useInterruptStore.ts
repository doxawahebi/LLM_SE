import { create } from "zustand";
import type { InterruptPoint } from "@/shared/contracts/sailor.types";

interface InterruptStore {
  interrupts: Map<string, InterruptPoint>;
  upsert: (ip: InterruptPoint) => void;
  markResolved: (interrupt_id: string, resolution: "resumed" | "skipped") => void;
  clearForRun: (run_id: string) => void;
}

export const useInterruptStore = create<InterruptStore>((set) => ({
  interrupts: new Map(),

  upsert: (ip) =>
    set((s) => {
      const next = new Map(s.interrupts);
      next.set(ip.interrupt_id, ip);
      return { interrupts: next };
    }),

  markResolved: (interrupt_id, resolution) =>
    set((s) => {
      const existing = s.interrupts.get(interrupt_id);
      if (!existing) return {};
      const next = new Map(s.interrupts);
      next.set(interrupt_id, {
        ...existing,
        status: resolution,
        resolved_at: new Date().toISOString(),
      });
      return { interrupts: next };
    }),

  clearForRun: (run_id) =>
    set((s) => {
      const next = new Map(s.interrupts);
      for (const [key, ip] of next) {
        if (ip.run_id === run_id) next.delete(key);
      }
      return { interrupts: next };
    }),
}));
