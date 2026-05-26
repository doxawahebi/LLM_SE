import { useState } from "react";
import type { Spec } from "@/lib/types";
import { StatusBadge } from "@/components/StatusBadge";
import { formatTokens, formatRelative } from "@/lib/formatters";

interface Props { spec: Spec }

export function SpecHeader({ spec }: Props) {
  const [expanded, setExpanded] = useState(false);

  const phases = [];
  if (spec.phase1_status) phases.push({ label: "P1", value: spec.phase1_status });
  if (spec.phase2_status) phases.push({ label: "P2", value: spec.phase2_status });
  if (spec.phase3_status) phases.push({ label: "P3", value: spec.phase3_status });

  return (
    <div className="bg-card border border-border rounded-lg p-4 mb-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h2 className="text-sm font-bold text-foreground">
            {spec.rule_id}
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            {spec.file}:{spec.line} · {spec.func}
          </p>
        </div>
        <div className="flex gap-2 items-center">
          {spec.verdict && <StatusBadge type="verdict" value={spec.verdict} />}
          {phases.map((p) => (
            <span key={p.label} className="text-xs text-muted-foreground">
              {p.label}: <span className="text-foreground">{p.value}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="flex gap-4 text-xs text-muted-foreground mb-3">
        <span>CWE: <span className="text-yellow-300">{spec.cwe}</span></span>
        {spec.current_turn !== null && (
          <span>Turn: <span className="text-foreground">{spec.current_turn}</span></span>
        )}
        <span>Tokens: <span className="text-foreground">{formatTokens(spec.token_cost)}</span></span>
        <span>Updated: <span className="text-foreground">{formatRelative(spec.last_updated)}</span></span>
      </div>

      <button
        onClick={() => setExpanded(!expanded)}
        className="text-xs text-primary hover:underline"
      >
        {expanded ? "Collapse" : "Expand"} spec JSON
      </button>

      {expanded && (
        <div className="mt-2 relative">
          <pre className="text-xs bg-muted rounded p-3 overflow-auto max-h-64 text-foreground">
            {JSON.stringify(spec, null, 2)}
          </pre>
          <button
            onClick={() => void navigator.clipboard.writeText(JSON.stringify(spec, null, 2))}
            className="absolute top-2 right-2 px-2 py-1 text-xs bg-secondary rounded hover:bg-accent transition-colors"
          >
            Copy
          </button>
        </div>
      )}
    </div>
  );
}
