import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listTurns, getTurn } from "@/api/specs";
import type { Turn, TurnPayload, LLMTurnPayload, CompileFailPayload, KleeRunPayload } from "@/lib/types";
import { formatTimestamp, formatDuration } from "@/lib/formatters";
import { cn } from "@/lib/cn";
import { PhaseDownloadButton } from "@/components/downloads/PhaseDownloadButton";
import { EvidencePackageButton } from "@/components/downloads/EvidencePackageButton";

interface Props { runId: string; specId: string; phase3Confirmed?: boolean }

export function Timeline({ runId, specId, phase3Confirmed }: Props) {
  const { data: turns, isLoading } = useQuery({
    queryKey: ["turns", runId, specId],
    queryFn: () => listTurns(runId, specId),
  });

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[1, 2, 3].map((i) => <div key={i} className="h-12 bg-muted rounded animate-pulse" />)}
      </div>
    );
  }

  if (!turns?.length) {
    return <p className="text-xs text-muted-foreground p-4">No timeline events yet.</p>;
  }

  return (
    <div className="space-y-1">
      {turns.map((turn) => (
        <TurnCard key={turn.id} turn={turn} runId={runId} specId={specId} />
      ))}

      {/* Phase completion download buttons at bottom of timeline */}
      {turns.length > 0 && (
        <div className="pt-2 flex flex-wrap gap-2">
          <PhaseDownloadButton
            runId={runId}
            specId={specId}
            phase={2}
            filename="outcome.json"
            label="↓ Phase 2 outcome"
          />
          {turns.some((t) => t.kind === "klee_run") && (
            <PhaseDownloadButton
              runId={runId}
              specId={specId}
              phase={2}
              filename="phase2_spec.tar.gz"
              label="↓ Phase 2 artifacts"
            />
          )}
          {phase3Confirmed && (
            <>
              <PhaseDownloadButton
                runId={runId}
                specId={specId}
                phase={3}
                filename="verified_bug.json"
                label="↓ verified_bug.json"
              />
              <PhaseDownloadButton
                runId={runId}
                specId={specId}
                phase={3}
                filename="phase3_spec.tar.gz"
                label="↓ Phase 3 artifacts"
              />
              <EvidencePackageButton runId={runId} specId={specId} />
            </>
          )}
        </div>
      )}
    </div>
  );
}

function TurnCard({ turn, runId, specId }: { turn: Turn; runId: string; specId: string }) {
  const [expanded, setExpanded] = useState(false);
  const [payload, setPayload] = useState<TurnPayload | null>(null);
  const [loading, setLoading] = useState(false);

  async function loadPayload() {
    if (payload || loading) return;
    setLoading(true);
    try {
      const full = await getTurn(runId, specId, turn.id);
      setPayload(full.payload);
    } finally {
      setLoading(false);
    }
  }

  const icon = turnIcon(turn.kind);
  const color = turnColor(turn.kind);

  return (
    <div className="border border-border rounded">
      <button
        className="w-full text-left px-3 py-2 flex items-center gap-3 hover:bg-accent/20 transition-colors"
        onClick={() => {
          setExpanded(!expanded);
          if (!expanded) void loadPayload();
        }}
      >
        <span className={cn("text-base", color)}>{icon}</span>
        <span className="text-xs text-muted-foreground w-20 shrink-0">
          {formatTimestamp(turn.started_at)}
        </span>
        <span className="text-xs text-muted-foreground w-8 shrink-0">
          T{turn.turn_number}
        </span>
        <span className={cn("text-xs font-mono", color)}>{turn.kind}</span>
        <span className="text-xs text-muted-foreground ml-auto">
          {formatDuration(turn.duration_ms)}
        </span>
      </button>

      {expanded && (
        <div className="px-3 pb-3 border-t border-border">
          {loading && <p className="text-xs text-muted-foreground py-2">Loading...</p>}
          {payload && <PayloadView payload={payload} />}
          {!loading && !payload && (
            <p className="text-xs text-muted-foreground py-2">No payload</p>
          )}
        </div>
      )}
    </div>
  );
}

function PayloadView({ payload }: { payload: TurnPayload }) {
  if ("prompt_tokens" in payload) {
    const p = payload as LLMTurnPayload;
    return (
      <div className="space-y-2 pt-2">
        <div className="text-xs text-muted-foreground">
          Tokens: {p.prompt_tokens} prompt + {p.completion_tokens} completion
        </div>
        <div className="text-xs text-foreground">{p.response_summary}</div>
        {p.tool_calls.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-1">Tool calls: {p.tool_calls.length}</p>
            {p.tool_calls.map((tc, i) => (
              <div key={i} className="text-xs font-mono text-blue-300">
                {tc.name}({JSON.stringify(tc.input).slice(0, 80)}...)
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  if ("raw_error" in payload) {
    const p = payload as CompileFailPayload;
    return (
      <div className="space-y-2 pt-2">
        <div className="text-xs text-red-300">Class: {p.error_class}</div>
        <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-48 text-foreground">
          {p.raw_error}
        </pre>
        {p.suggested_fix && (
          <div>
            <p className="text-xs text-muted-foreground mb-1">Suggested fix:</p>
            <pre className="text-xs bg-muted rounded p-2 overflow-auto text-green-300">
              {p.suggested_fix}
            </pre>
          </div>
        )}
      </div>
    );
  }

  if ("outcome" in payload) {
    const p = payload as KleeRunPayload;
    return (
      <div className="space-y-2 pt-2">
        <div className={cn("text-xs font-semibold", p.outcome === "bug_triggered" ? "text-orange-300" : "text-foreground")}>
          Outcome: {p.outcome}
        </div>
        <div className="text-xs text-muted-foreground">
          Paths explored: {p.paths_explored}
        </div>
        {p.functions_entered.length > 0 && (
          <div className="text-xs">
            <span className="text-muted-foreground">Entered: </span>
            {p.functions_entered.join(", ")}
          </div>
        )}
        {p.functions_missed.length > 0 && (
          <div className="text-xs text-red-300">
            <span className="text-muted-foreground">Missed: </span>
            {p.functions_missed.join(", ")}
          </div>
        )}
        {p.stderr_excerpt && (
          <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-48 text-muted-foreground">
            {p.stderr_excerpt}
          </pre>
        )}
      </div>
    );
  }

  return (
    <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-48 text-foreground pt-2">
      {JSON.stringify(payload, null, 2)}
    </pre>
  );
}

function turnIcon(kind: string): string {
  switch (kind) {
    case "explore": return "◐";
    case "author": return "◐";
    case "refinement": return "◐";
    case "compile_fail": return "◑";
    case "klee_run": return "✓";
    case "intervention": return "⚑";
    case "klee_timeout": return "⌛";
    default: return "●";
  }
}

function turnColor(kind: string): string {
  switch (kind) {
    case "compile_fail": return "text-red-400";
    case "klee_run": return "text-green-400";
    case "intervention": return "text-yellow-400";
    default: return "text-blue-400";
  }
}
