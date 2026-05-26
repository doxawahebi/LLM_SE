import type { InterruptPoint } from "@/api/client";

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function CompileDiagInterrupt({ interrupt }: Props) {
  const diag = interrupt.option_overrides?.compile_diagnostic as {
    error_class?: string;
    raw_error?: string;
    suggested_fix?: string;
    relevant_source?: string;
  } | undefined;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Compile & Diagnose
      </p>

      {diag?.error_class && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Error class:</span>
          <span className="px-2 py-0.5 text-xs bg-red-900/30 text-red-300 border border-red-700/30 rounded font-mono">
            {diag.error_class}
          </span>
        </div>
      )}

      {diag?.raw_error && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Compiler output:</p>
          <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-32 text-red-300 whitespace-pre-wrap">
            {diag.raw_error}
          </pre>
        </div>
      )}

      {diag?.relevant_source && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Relevant source:</p>
          <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-20 text-foreground whitespace-pre-wrap">
            {diag.relevant_source}
          </pre>
        </div>
      )}

      {diag?.suggested_fix && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Suggested fix:</p>
          <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-20 text-green-300 whitespace-pre-wrap">
            {diag.suggested_fix}
          </pre>
          <p className="text-xs text-muted-foreground">
            Apply the fix to the relevant file using [Edit] above, then click Resume.
            The server will re-run compilation before accepting.
          </p>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Edit <code>driver.c</code>, <code>slice.c</code>, or <code>stubs.c</code> using the
        file rows above, then click "Resume with current inputs".
      </p>

      {interrupt.input_files.length === 0 && (
        <p className="text-xs text-muted-foreground">
          No harness files available — use the file rows above.
        </p>
      )}
    </div>
  );
}
