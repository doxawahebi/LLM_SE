import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function SpecGenInterrupt({ interrupt, overrides, setOverrides }: Props) {
  const factPacks = interrupt.input_files.find((f) => f.name.includes("fact_pack"));
  const fileSkip = (overrides.file_skip_patterns as string) ?? "";
  const funcSkip = (overrides.function_skip_patterns as string) ?? "";

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Spec Generation
      </p>

      {factPacks && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          {factPacks.name} — {Math.round(factPacks.size / 1024)}KB — use [Edit] / [Replace ↑] above
        </div>
      )}

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">
          File skip patterns (one per line, glob syntax)
        </label>
        <textarea
          value={fileSkip}
          onChange={(e) => setOverrides({ ...overrides, file_skip_patterns: e.target.value })}
          rows={3}
          className="w-full px-2 py-1 text-xs font-mono bg-secondary border border-border rounded text-foreground resize-y"
          placeholder="tests/**&#10;*.pb.c"
        />
      </div>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">
          Function skip patterns (one per line)
        </label>
        <textarea
          value={funcSkip}
          onChange={(e) => setOverrides({ ...overrides, function_skip_patterns: e.target.value })}
          rows={3}
          className="w-full px-2 py-1 text-xs font-mono bg-secondary border border-border rounded text-foreground resize-y"
          placeholder="test_*&#10;debug_*"
        />
      </div>
    </div>
  );
}
