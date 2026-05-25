import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  modifiedFiles: Map<string, string>;
}

interface StubEntry {
  function: string;
  granularity: "function" | "branch" | "loop" | "type";
  return_value: string;
}

export function StubSynthInterrupt({ interrupt }: Props) {
  const sliceFile = interrupt.input_files.find(
    (f) => f.name.includes("slice") && f.name.endsWith(".c")
  );
  const stubs: StubEntry[] = Array.isArray(interrupt.option_overrides?.stub_summary)
    ? (interrupt.option_overrides.stub_summary as StubEntry[])
    : [];

  const hasFreeStubWithoutRealFree =
    stubs.some((s) => s.function === "free" && s.return_value !== "real_free");

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Stub Synthesis
      </p>

      {sliceFile && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          📄 {sliceFile.name} — use [Edit] / [Replace ↑] above
        </div>
      )}

      {hasFreeStubWithoutRealFree && (
        <div className="bg-red-900/20 border border-red-700/40 rounded p-2 text-xs text-red-300">
          <strong>⚠ free() stub must call real free() for CWE-416 (paper §4.2).</strong>
          {" "}Fix before resuming.
        </div>
      )}

      {stubs.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">Stub summary:</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th className="text-left py-1">Function</th>
                <th className="text-left py-1">Granularity</th>
                <th className="text-left py-1">Return value</th>
              </tr>
            </thead>
            <tbody>
              {stubs.map((s, i) => (
                <tr key={i} className="border-b border-border/50 font-mono">
                  <td className="py-1 text-foreground">{s.function}()</td>
                  <td className="py-1 text-muted-foreground">{s.granularity}</td>
                  <td className="py-1 text-muted-foreground">{s.return_value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
