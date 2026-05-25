import { useQuery } from "@tanstack/react-query";
import { getResults } from "@/api/specs";
import { exportResults } from "@/api/artifacts";
import { formatTimestamp } from "@/lib/formatters";
import type { VerifiedBug } from "@/lib/types";

interface Props { runId: string }

export function RunResultsTab({ runId }: Props) {
  const { data: bugs, isLoading } = useQuery({
    queryKey: ["results", runId],
    queryFn: () => getResults(runId),
  });

  if (isLoading) {
    return (
      <div className="space-y-2 p-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-10 bg-muted rounded animate-pulse" />
        ))}
      </div>
    );
  }

  if (!bugs?.length) {
    return (
      <div className="p-8 text-center text-muted-foreground text-sm">
        No confirmed vulnerabilities yet.
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="flex justify-between items-center mb-3">
        <h2 className="text-sm font-semibold text-foreground">
          {bugs.length} confirmed vulnerabilities
        </h2>
        <button
          onClick={() => void exportResults(runId)}
          className="px-3 py-1.5 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors"
        >
          Export all as tarball
        </button>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="grid grid-cols-[80px_80px_1fr_1fr_1fr_80px_100px] gap-2 px-3 py-2 border-b border-border text-xs text-muted-foreground bg-muted/30">
          <div>CWE</div>
          <div>ASan type</div>
          <div>File:line</div>
          <div>Function</div>
          <div>Witness</div>
          <div>First seen</div>
          <div>Actions</div>
        </div>
        {bugs.map((bug: VerifiedBug) => (
          <div
            key={`${bug.spec_id}`}
            className="grid grid-cols-[80px_80px_1fr_1fr_1fr_80px_100px] gap-2 px-3 py-2 border-b border-border/50 text-xs hover:bg-accent/20 transition-colors"
          >
            <div className="text-yellow-300">{bug.cwe}</div>
            <div className="text-red-300">{bug.asan_type}</div>
            <div className="truncate text-blue-300">
              {bug.file.split("/").at(-1)}:{bug.line}
            </div>
            <div className="truncate">{bug.func}</div>
            <div className="truncate text-muted-foreground">{bug.witness_summary}</div>
            <div className="text-muted-foreground">{formatTimestamp(bug.first_seen)}</div>
            <div>
              <span
                className={`inline-block w-2 h-2 rounded-full mr-1 ${
                  bug.replay_still_crashes ? "bg-green-500" : "bg-red-500"
                }`}
              />
              {bug.replay_still_crashes ? "stable" : "flaky"}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
