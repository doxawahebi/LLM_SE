import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  modifiedFiles: Map<string, string>;
}

export function DriverSynthInterrupt({ interrupt }: Props) {
  const driverFile = interrupt.input_files.find(
    (f) => f.name.includes("driver") && f.name.endsWith(".c")
  );
  const specFile = interrupt.input_files.find((f) => f.name.includes("spec"));

  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Driver Synthesis
      </p>
      <p className="text-xs text-muted-foreground">
        Review the LLM-generated <code>driver.c</code> before compilation. You can edit it
        or replace it with a custom driver. The server will validate it compiles before accepting.
      </p>
      {driverFile && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          📄 {driverFile.name} — use [Edit] / [Replace ↑] above
        </div>
      )}
      {specFile && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          📄 {specFile.name} (reference, read-only) — use [View] above
        </div>
      )}
    </div>
  );
}
