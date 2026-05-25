import type { InterruptPoint } from "@/api/client";

const SEARCH_STRATEGIES = [
  "random-path",
  "dfs",
  "bfs",
  "nurs:covnew",
  "nurs:md2u",
  "nurs:ic",
] as const;

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function KLEEExecInterrupt({ interrupt, overrides, setOverrides }: Props) {
  const strategies: string[] = Array.isArray(overrides.search_strategies)
    ? (overrides.search_strategies as string[])
    : ["random-path", "dfs"];
  const timeout = (overrides.timeout as number) ?? 300;
  const depthLimit = (overrides.depth_limit as number) ?? 1000;

  const coverage = interrupt.option_overrides?.coverage as {
    entered?: string[];
    missed?: string[];
  } | undefined;

  function toggleStrategy(s: string) {
    const next = strategies.includes(s)
      ? strategies.filter((x) => x !== s)
      : [...strategies, s];
    setOverrides({ ...overrides, search_strategies: next });
  }

  const timeoutInvalid = timeout <= 0 || timeout > 3600;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        KLEE Execution Options
      </p>

      <div className="space-y-1">
        <p className="text-xs text-muted-foreground">Search strategies:</p>
        <div className="flex flex-wrap gap-1">
          {SEARCH_STRATEGIES.map((s) => (
            <button
              key={s}
              onClick={() => toggleStrategy(s)}
              className={`px-2 py-0.5 text-xs rounded transition-colors ${
                strategies.includes(s)
                  ? "bg-primary/20 text-primary border border-primary/40"
                  : "bg-secondary text-muted-foreground hover:bg-accent"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
        {strategies.length === 0 && (
          <p className="text-xs text-red-400">At least 1 strategy required.</p>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-0.5">
          <label className="text-xs text-muted-foreground">Timeout (seconds)</label>
          <input
            type="number"
            value={timeout}
            min={1}
            max={3600}
            onChange={(e) => setOverrides({ ...overrides, timeout: Number(e.target.value) })}
            className={`w-full px-2 py-1 text-xs bg-secondary border rounded text-foreground ${
              timeoutInvalid ? "border-red-500" : "border-border"
            }`}
          />
          {timeoutInvalid && (
            <p className="text-xs text-red-400">Must be 1–3600s</p>
          )}
        </div>
        <div className="space-y-0.5">
          <label className="text-xs text-muted-foreground">Depth limit</label>
          <input
            type="number"
            value={depthLimit}
            min={1}
            onChange={(e) => setOverrides({ ...overrides, depth_limit: Number(e.target.value) })}
            className="w-full px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
          />
        </div>
      </div>

      {coverage && (
        <div className="space-y-1 text-xs">
          {coverage.entered && coverage.entered.length > 0 && (
            <p className="text-muted-foreground">
              <span className="text-green-300">Entered:</span>{" "}
              {coverage.entered.join(", ")}
            </p>
          )}
          {coverage.missed && coverage.missed.length > 0 && (
            <p className="text-muted-foreground">
              <span className="text-red-300">Missed:</span>{" "}
              {coverage.missed.join(", ")}
            </p>
          )}
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Note: <code>harness.bc</code> is binary and cannot be edited here.
        To change the harness, use the Driver Synthesis interrupt first.
      </p>
    </div>
  );
}
