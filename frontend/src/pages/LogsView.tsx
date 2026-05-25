import { useState, useRef, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { getLogs, type LogFilters } from "@/api/settings";
import type { LogLine } from "@/lib/types";
import { formatTimestamp } from "@/lib/formatters";
import { cn } from "@/lib/cn";

export function LogsView() {
  const { run_id } = useParams<{ run_id: string }>();
  const navigate = useNavigate();
  const [tail, setTail] = useState(true);
  const [filters, setFilters] = useState<LogFilters>({ limit: 1000 });
  const parentRef = useRef<HTMLDivElement>(null);

  const { data: logs = [] } = useQuery({
    queryKey: ["logs", run_id, filters],
    queryFn: () => getLogs(run_id!, filters),
    enabled: !!run_id,
    refetchInterval: tail ? 3_000 : false,
  });

  // eslint-disable-next-line react-hooks/incompatible-library
  const rowVirtualizer = useVirtualizer({
    count: logs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 24,
    overscan: 20,
  });

  // Auto-scroll to bottom in tail mode
  useEffect(() => {
    if (tail && parentRef.current) {
      parentRef.current.scrollTop = parentRef.current.scrollHeight;
    }
  }, [logs, tail]);

  return (
    <div className="p-6 max-w-7xl mx-auto h-screen flex flex-col">
      <div className="flex items-center gap-2 mb-4 text-xs text-muted-foreground">
        <button onClick={() => navigate(`/runs/${run_id}`)} className="hover:text-foreground">
          Run
        </button>
        <span>/</span>
        <span className="text-foreground">Logs</span>
      </div>

      {/* Filter bar */}
      <div className="flex gap-2 mb-3 flex-wrap">
        <select
          value={filters.level ?? ""}
          onChange={(e) => setFilters((f) => ({ ...f, level: e.target.value || undefined }))}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
        >
          <option value="">All levels</option>
          <option value="error">error</option>
          <option value="warn">warn</option>
          <option value="info">info</option>
          <option value="debug">debug</option>
        </select>

        <select
          value={filters.source ?? ""}
          onChange={(e) => setFilters((f) => ({ ...f, source: e.target.value || undefined }))}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
        >
          <option value="">All sources</option>
          {["celery", "phase1", "phase2", "phase3", "llm", "klee", "clang", "asan"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Spec ID..."
          value={filters.spec_id ?? ""}
          onChange={(e) => setFilters((f) => ({ ...f, spec_id: e.target.value || undefined }))}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground w-36"
        />

        <button
          onClick={() => setTail(!tail)}
          className={cn(
            "px-3 py-1 text-xs rounded transition-colors",
            tail ? "bg-primary text-primary-foreground" : "bg-secondary hover:bg-accent"
          )}
        >
          {tail ? "Tailing" : "Resume tailing"}
        </button>

        <span className="ml-auto text-xs text-muted-foreground self-center">
          {logs.length.toLocaleString()} lines
        </span>
      </div>

      {/* Log lines — virtualized */}
      <div
        ref={parentRef}
        className="flex-1 bg-card border border-border rounded overflow-auto font-mono"
      >
        <div style={{ height: rowVirtualizer.getTotalSize(), position: "relative" }}>
          {rowVirtualizer.getVirtualItems().map((vrow) => {
            const line = logs[vrow.index];
            return (
              <div
                key={vrow.index}
                data-index={vrow.index}
                ref={rowVirtualizer.measureElement}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${vrow.start}px)`,
                }}
                className="flex gap-2 px-3 py-0.5 text-xs border-b border-border/30 hover:bg-accent/10"
              >
                <span className="text-muted-foreground w-20 shrink-0">
                  {formatTimestamp(line.timestamp)}
                </span>
                <span className={cn("w-12 shrink-0", levelColor(line.level))}>
                  {line.level.toUpperCase()}
                </span>
                <span className="text-blue-300 w-16 shrink-0">{line.source}</span>
                {line.spec_id && (
                  <span className="text-muted-foreground w-16 shrink-0">
                    {line.spec_id.slice(-6)}
                  </span>
                )}
                <span className="text-foreground flex-1 break-all">{line.message}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function levelColor(level: LogLine["level"]): string {
  switch (level) {
    case "error": return "text-red-400";
    case "warn": return "text-yellow-400";
    case "info": return "text-green-400";
    case "debug": return "text-muted-foreground";
  }
}
