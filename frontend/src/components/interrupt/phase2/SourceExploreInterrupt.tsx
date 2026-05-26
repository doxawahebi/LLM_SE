import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function SourceExploreInterrupt({ interrupt, overrides, setOverrides }: Props) {
  const specFile = interrupt.input_files.find((f) => f.name.includes("spec"));

  const T_explore = (overrides.T_explore as number) ?? 8;
  const T_author = (overrides.T_author as number) ?? 12;
  const T_max = (overrides.T_max as number) ?? 60;
  const R_max = (overrides.R_max as number) ?? 15;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Source Exploration
      </p>

      {specFile && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          {specFile.name} — use [Edit] / [Replace ↑] above to modify spec.json
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Adjust turn budgets (apply to this spec only):
      </p>

      <div className="grid grid-cols-4 gap-2">
        {([
          ["T_explore", T_explore, "Explore turns"],
          ["T_author", T_author, "Author turns"],
          ["T_max", T_max, "Max turns"],
          ["R_max", R_max, "Max refine"],
        ] as [string, number, string][]).map(([key, val, label]) => (
          <div key={key} className="space-y-0.5">
            <label className="text-xs text-muted-foreground">{label}</label>
            <input
              type="number"
              value={val}
              min={1}
              onChange={(e) =>
                setOverrides({ ...overrides, [key]: Number(e.target.value) })
              }
              className="w-full px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
            />
          </div>
        ))}
      </div>

      {T_explore + T_author > T_max && (
        <p className="text-xs text-red-400">
          T_explore + T_author ({T_explore + T_author}) must be ≤ T_max ({T_max}).
        </p>
      )}
    </div>
  );
}
