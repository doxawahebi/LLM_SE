import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function ASanCompileInterrupt({ interrupt, overrides, setOverrides }: Props) {
  const asanCmd = (overrides.asan_build_command as string) ??
    (interrupt.option_overrides?.asan_build_command as string) ?? "";
  const asanOptions = (overrides.asan_options as string) ??
    "halt_on_error=1:print_stacktrace=1";
  const stubDetected = interrupt.option_overrides?.stub_files_detected as string[] | undefined;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        ASan Compilation
      </p>

      {stubDetected && stubDetected.length > 0 && (
        <div className="bg-red-900/20 border border-red-700/40 rounded p-2 space-y-1">
          <p className="text-xs text-red-300 font-semibold">
            ✖ Error: LLM-generated stub files detected in compile command (must be removed):
          </p>
          {stubDetected.map((f, i) => (
            <p key={i} className="text-xs font-mono text-red-300 ml-2">{f}</p>
          ))}
          <p className="text-xs text-red-300">
            ASan must compile ONLY unmodified project source files.
          </p>
        </div>
      )}

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">ASan build command</label>
        <input
          type="text"
          value={asanCmd}
          onChange={(e) => setOverrides({ ...overrides, asan_build_command: e.target.value })}
          className="w-full px-3 py-2 text-xs font-mono bg-secondary border border-border rounded text-foreground"
          placeholder="make CFLAGS='-fsanitize=address -O1 -g'"
        />
      </div>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">ASAN_OPTIONS</label>
        <input
          type="text"
          value={asanOptions}
          onChange={(e) => setOverrides({ ...overrides, asan_options: e.target.value })}
          className="w-full px-3 py-2 text-xs font-mono bg-secondary border border-border rounded text-foreground"
        />
      </div>

      <label className="flex items-center gap-2 text-xs cursor-pointer">
        <input
          type="checkbox"
          checked={true}
          readOnly
          className="w-3 h-3"
        />
        <span className="text-muted-foreground">
          Confirm unmodified project source is used (verified server-side)
        </span>
      </label>
    </div>
  );
}
