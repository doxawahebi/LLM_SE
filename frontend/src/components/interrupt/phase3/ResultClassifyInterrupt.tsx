import type { InterruptPoint } from "@/api/client";

const VERDICTS = ["CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE"] as const;
type VerdictOption = (typeof VERDICTS)[number];

const CWE_OPTIONS = [
  "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124", "CWE-125",
  "CWE-190", "CWE-401", "CWE-415", "CWE-416", "CWE-457", "CWE-476",
] as const;

interface StackFrame {
  frame: number;
  file: string;
  func: string;
  in_project_source: boolean;
}

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function ResultClassifyInterrupt({ interrupt, overrides, setOverrides }: Props) {
  const auto = interrupt.option_overrides as {
    proposed_verdict?: string;
    cwe?: string;
    stack_frames?: StackFrame[];
    asan_output?: string;
  } | undefined;

  const verdict = (overrides.verdict as VerdictOption) ?? (auto?.proposed_verdict as VerdictOption) ?? "CONFIRMED";
  const cwe = (overrides.cwe as string) ?? auto?.cwe ?? "";
  const reason = (overrides.reason as string) ?? "";
  const frames: StackFrame[] = auto?.stack_frames ?? [];

  const noProjectSourceFrame = !frames.some((f) => f.in_project_source);
  const showWarning = verdict === "CONFIRMED" && noProjectSourceFrame;

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
        Result Classification
      </p>

      {auto?.asan_output && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">ASan output:</p>
          <pre className="text-xs bg-muted rounded p-2 overflow-auto max-h-24 text-foreground whitespace-pre-wrap">
            {auto.asan_output}
          </pre>
        </div>
      )}

      {frames.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground mb-1">Stack trace:</p>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th className="text-left py-1">Frame</th>
                <th className="text-left py-1">File</th>
                <th className="text-left py-1">Function</th>
                <th className="text-left py-1">Project?</th>
              </tr>
            </thead>
            <tbody>
              {frames.map((f, i) => (
                <tr key={i} className="border-b border-border/50 font-mono">
                  <td className="py-1 text-muted-foreground">#{f.frame}</td>
                  <td className="py-1 text-foreground truncate max-w-32">{f.file}</td>
                  <td className="py-1 text-muted-foreground truncate max-w-32">{f.func}</td>
                  <td className="py-1">
                    {f.in_project_source ? (
                      <span className="text-green-300">✅ YES</span>
                    ) : (
                      <span className="text-muted-foreground">❌ NO</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Proposed verdict</label>
        <select
          value={verdict}
          onChange={(e) => setOverrides({ ...overrides, verdict: e.target.value })}
          className="w-full px-3 py-2 text-xs bg-secondary border border-border rounded text-foreground"
        >
          {VERDICTS.map((v) => (
            <option key={v} value={v}>{v}</option>
          ))}
        </select>
      </div>

      {showWarning && (
        <div className="bg-yellow-900/20 border border-yellow-700/40 rounded p-2 text-xs text-yellow-300">
          ⚠ No project source frame detected. Confirm override is intentional.
        </div>
      )}

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Override CWE</label>
        <select
          value={cwe}
          onChange={(e) => setOverrides({ ...overrides, cwe: e.target.value })}
          className="w-full px-3 py-2 text-xs bg-secondary border border-border rounded text-foreground"
        >
          <option value="">— auto-classify —</option>
          {CWE_OPTIONS.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
      </div>

      <div className="space-y-1">
        <label className="text-xs text-muted-foreground">Reason (optional)</label>
        <input
          type="text"
          value={reason}
          onChange={(e) => setOverrides({ ...overrides, reason: e.target.value })}
          placeholder="Explain override…"
          className="w-full px-3 py-2 text-xs bg-secondary border border-border rounded text-foreground"
        />
      </div>
    </div>
  );
}
