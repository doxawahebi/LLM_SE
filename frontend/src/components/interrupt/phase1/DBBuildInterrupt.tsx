import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function DBBuildInterrupt({ overrides, setOverrides }: Props) {
  const buildCmd = (overrides.build_command as string) ?? "";
  const useExisting = (overrides.use_existing_db as boolean) ?? false;
  const dbPath = (overrides.db_path as string) ?? "";

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        CodeQL DB Build Options
      </p>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Build command</label>
        <input
          type="text"
          value={buildCmd}
          onChange={(e) => setOverrides({ ...overrides, build_command: e.target.value })}
          className="w-full px-3 py-2 text-xs font-mono bg-secondary border border-border rounded text-foreground"
          placeholder="./configure && make"
        />
      </div>

      <label className="flex items-center gap-2 text-xs cursor-pointer">
        <input
          type="checkbox"
          checked={useExisting}
          onChange={(e) => setOverrides({ ...overrides, use_existing_db: e.target.checked })}
          className="w-3 h-3"
        />
        <span className="text-muted-foreground">Use existing CodeQL DB</span>
      </label>

      {useExisting && (
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">CodeQL DB path</label>
          <input
            type="text"
            value={dbPath}
            onChange={(e) => setOverrides({ ...overrides, db_path: e.target.value })}
            className="w-full px-3 py-2 text-xs font-mono bg-secondary border border-border rounded text-foreground"
            placeholder="/path/to/codeql-db"
          />
        </div>
      )}

      {!buildCmd && !useExisting && (
        <p className="text-xs text-red-400">Build command required, or use an existing DB.</p>
      )}
    </div>
  );
}
