import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  modifiedFiles: Map<string, string>;
}

export function ReplayDriverInterrupt({ interrupt }: Props) {
  const replayFile = interrupt.input_files.find((f) =>
    f.name.includes("replay_driver")
  );

  const witnessValues = interrupt.option_overrides?.witness_values as Array<{
    variable: string;
    type: string;
    value: string;
  }> | undefined;

  const kleeCalls = interrupt.option_overrides?.klee_calls_found as string[] | undefined;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Replay Driver Generation
      </p>

      {replayFile && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          📄 {replayFile.name} — use [Edit] / [Replace ↑] above
        </div>
      )}

      {kleeCalls && kleeCalls.length > 0 && (
        <div className="bg-red-900/20 border border-red-700/40 rounded p-2 space-y-1">
          <p className="text-xs text-red-300 font-semibold">
            ✖ Error: klee_* calls found in replay_driver.c (must be removed):
          </p>
          {kleeCalls.map((call, i) => (
            <p key={i} className="text-xs font-mono text-red-300 ml-2">{call}</p>
          ))}
          <p className="text-xs text-red-300">
            Resume blocked until all klee_* calls are removed.
          </p>
        </div>
      )}

      {witnessValues && witnessValues.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">Witness values (from .ktest):</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th className="text-left py-1">Variable</th>
                <th className="text-left py-1">Type</th>
                <th className="text-left py-1">Value</th>
              </tr>
            </thead>
            <tbody>
              {witnessValues.map((w, i) => (
                <tr key={i} className="border-b border-border/50 font-mono">
                  <td className="py-1 text-foreground">{w.variable}</td>
                  <td className="py-1 text-muted-foreground">{w.type}</td>
                  <td className="py-1 text-muted-foreground">{w.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Regular assignments (e.g., <code>ndo-&gt;ndo_vflag = 3</code>) must be preserved.
        The driver will be compiled with <code>clang -fsanitize=address</code> before accepting.
      </p>
    </div>
  );
}
