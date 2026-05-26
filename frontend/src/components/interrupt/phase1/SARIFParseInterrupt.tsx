import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
}

export function SARIFParseInterrupt({ interrupt }: Props) {
  const sarif = interrupt.input_files.find(
    (f) => f.name.endsWith(".sarif") || f.name.includes("findings")
  );

  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        SARIF Parsing
      </p>
      <p className="text-xs text-muted-foreground">
        Review the SARIF file below. You can replace it with a custom SARIF before parsing continues.
        The file must be valid JSON with a "runs" array (SARIF 2.1.0 schema).
      </p>
      {sarif && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          {sarif.name} — use the [View] / [Replace ↑] buttons above
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        A warning will appear if findings count = 0 (non-blocking).
      </p>
    </div>
  );
}
