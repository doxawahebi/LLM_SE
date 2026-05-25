import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
}

export function FactEnrichInterrupt({ interrupt }: Props) {
  const findings = interrupt.input_files.find((f) => f.name.includes("findings"));

  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Fact Enrichment
      </p>
      <p className="text-xs text-muted-foreground">
        Edit or replace <code>findings.json</code> before fact enrichment runs.
        You can remove, edit, or add findings.
      </p>
      {findings && (
        <div className="text-xs text-muted-foreground bg-secondary/30 rounded p-2 font-mono">
          {findings.name} — {Math.round(findings.size / 1024)}KB — use [Edit] / [Replace ↑] above
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        Schema: JSON array of objects with{" "}
        <code>finding_id, rule_id, cwe, location.file, location.line, description</code>.
      </p>
    </div>
  );
}
