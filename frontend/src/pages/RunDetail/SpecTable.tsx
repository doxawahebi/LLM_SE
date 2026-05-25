import { useRef, useMemo, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useQueryClient } from "@tanstack/react-query";
import { useSpecStore } from "@/hooks/useSpecStore";
import { StatusBadge } from "@/components/StatusBadge";
import { formatRelative } from "@/lib/formatters";
import { requeueSpec, skipSpec, bulkRequeue, bulkSkip } from "@/api/specs";
import { cn } from "@/lib/cn";

// nuqs filter state
import { useQueryState } from "nuqs";

interface Props {
  runId: string;
}

export function SpecTable({ runId }: Props) {
  const navigate = useNavigate();
  const parentRef = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; specId: string } | null>(null);

  // URL-encoded filter state
  const [phaseFilter, setPhaseFilter] = useQueryState("phase", { defaultValue: "" });
  const [verdictFilter, setVerdictFilter] = useQueryState("verdict", { defaultValue: "" });
  const [cweFilter, setCweFilter] = useQueryState("cwe", { defaultValue: "" });
  const [search, setSearch] = useQueryState("q", { defaultValue: "" });

  const specMap = useSpecStore((s) => s.specs);
  const queryClient = useQueryClient();

  const filteredSpecs = useMemo(() => {
    const all = Array.from(specMap.values()).filter((s) => s.run_id === runId);
    return all.filter((s) => {
      if (phaseFilter && s.phase1_status !== phaseFilter &&
          s.phase2_status !== phaseFilter && s.phase3_status !== phaseFilter) return false;
      if (verdictFilter && s.verdict !== verdictFilter) return false;
      if (cweFilter && !s.cwe.includes(cweFilter)) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!s.message.toLowerCase().includes(q) &&
            !s.file.toLowerCase().includes(q) &&
            !s.func.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [specMap, runId, phaseFilter, verdictFilter, cweFilter, search]);

  // eslint-disable-next-line react-hooks/incompatible-library
  const rowVirtualizer = useVirtualizer({
    count: filteredSpecs.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 40,
    overscan: 20,
  });

  const toggleSelect = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleContextMenu = useCallback((e: React.MouseEvent, specId: string) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, specId });
  }, []);

  async function handleBulkAction(action: "requeue" | "skip") {
    const ids = Array.from(selected);
    if (action === "requeue") await bulkRequeue(runId, ids);
    else await bulkSkip(runId, ids);
    setSelected(new Set());
    void queryClient.invalidateQueries({ queryKey: ["specs", runId] });
  }

  return (
    <div className="bg-card border border-border rounded-lg flex flex-col h-[600px]">
      {/* Filter bar */}
      <div className="flex gap-2 p-3 border-b border-border items-center">
        <input
          type="text"
          placeholder="Search message/file/func..."
          value={search}
          onChange={(e) => void setSearch(e.target.value)}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground w-48"
        />
        <select
          value={phaseFilter}
          onChange={(e) => void setPhaseFilter(e.target.value)}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
        >
          <option value="">All phases</option>
          <option value="emitted">Phase 1: emitted</option>
          <option value="filtered">Phase 1: filtered</option>
          <option value="bug_triggered">P2: triggered</option>
          <option value="inconclusive">P2: inconclusive</option>
          <option value="confirmed">P3: confirmed</option>
          <option value="rejected">P3: rejected</option>
        </select>
        <select
          value={verdictFilter}
          onChange={(e) => void setVerdictFilter(e.target.value)}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
        >
          <option value="">All verdicts</option>
          <option value="CONFIRMED">CONFIRMED</option>
          <option value="inconclusive">inconclusive</option>
          <option value="likely_false_positive">likely FP</option>
          <option value="rejected">rejected</option>
        </select>
        <input
          type="text"
          placeholder="CWE..."
          value={cweFilter}
          onChange={(e) => void setCweFilter(e.target.value)}
          className="px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground w-24"
        />
        <span className="ml-auto text-xs text-muted-foreground">
          {filteredSpecs.length.toLocaleString()} specs
        </span>
        {selected.size > 0 && (
          <div className="flex gap-1">
            <button
              onClick={() => void handleBulkAction("requeue")}
              className="px-2 py-1 text-xs bg-primary text-primary-foreground rounded"
            >
              Re-queue {selected.size}
            </button>
            <button
              onClick={() => void handleBulkAction("skip")}
              className="px-2 py-1 text-xs bg-secondary hover:bg-accent rounded"
            >
              Skip {selected.size}
            </button>
          </div>
        )}
      </div>

      {/* Table header */}
      <div className="grid grid-cols-[24px_80px_60px_1fr_1fr_80px_80px_60px_80px_100px] gap-1 px-3 py-1.5 border-b border-border text-xs text-muted-foreground bg-muted/30 sticky top-0">
        <div />
        <div>#</div>
        <div>CWE</div>
        <div>File</div>
        <div>Func</div>
        <div>Phase</div>
        <div>Status</div>
        <div>Turn</div>
        <div>Last</div>
        <div>Verdict</div>
      </div>

      {/* Virtualized rows */}
      <div ref={parentRef} className="flex-1 overflow-auto">
        <div
          style={{ height: rowVirtualizer.getTotalSize(), position: "relative" }}
        >
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const spec = filteredSpecs[virtualRow.index];
            const isSelected = selected.has(spec.id);
            return (
              <div
                key={spec.id}
                data-index={virtualRow.index}
                ref={rowVirtualizer.measureElement}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                className={cn(
                  "grid grid-cols-[24px_80px_60px_1fr_1fr_80px_80px_60px_80px_100px] gap-1 px-3 py-1.5 text-xs border-b border-border/50 cursor-pointer hover:bg-accent/30 transition-colors",
                  isSelected && "bg-primary/10",
                  spec.error_class && "border-l-2 border-l-red-500"
                )}
                onClick={() => navigate(`/runs/${runId}/specs/${spec.id}`)}
                onContextMenu={(e) => handleContextMenu(e, spec.id)}
              >
                <div onClick={(e) => toggleSelect(spec.id, e)}>
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => { /* handled by click */ }}
                    className="w-3 h-3"
                  />
                </div>
                <div className="truncate text-muted-foreground font-mono">
                  {spec.id.slice(-6)}
                </div>
                <div className="text-yellow-300">{spec.cwe}</div>
                <div className="truncate text-muted-foreground">
                  {spec.file.split("/").at(-1)}:{spec.line}
                </div>
                <div className="truncate">{spec.func}</div>
                <div>
                  <span className="text-xs">
                    {spec.phase3_status ? `P3: ${spec.phase3_status}` :
                     spec.phase2_status ? `P2: ${spec.phase2_status}` :
                     `P1: ${spec.phase1_status}`}
                  </span>
                </div>
                <div>
                  {spec.error_class ? (
                    <span className="text-red-400 text-xs">{spec.error_class}</span>
                  ) : (
                    <span className="text-green-400 text-xs">ok</span>
                  )}
                </div>
                <div className="text-muted-foreground">
                  {spec.current_turn !== null
                    ? `${spec.current_turn}/${spec.phase2_status ? 60 : "-"}`
                    : "-"}
                </div>
                <div className="text-muted-foreground">
                  {formatRelative(spec.last_updated)}
                </div>
                <div>
                  {spec.verdict && (
                    <StatusBadge type="verdict" value={spec.verdict} />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          specId={contextMenu.specId}
          runId={runId}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
}

function ContextMenu({
  x, y, specId, runId, onClose,
}: {
  x: number; y: number; specId: string; runId: string; onClose: () => void;
}) {
  const navigate = useNavigate();
  const specMap = useSpecStore((s) => s.specs);
  const spec = specMap.get(specId);

  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} />
      <div
        className="fixed z-50 bg-popover border border-border rounded shadow-xl text-xs min-w-40"
        style={{ left: x, top: y }}
      >
        <button
          className="w-full px-3 py-2 text-left hover:bg-accent transition-colors"
          onClick={() => { void requeueSpec(runId, specId); onClose(); }}
        >
          Re-queue
        </button>
        <button
          className="w-full px-3 py-2 text-left hover:bg-accent transition-colors"
          onClick={() => { void skipSpec(runId, specId); onClose(); }}
        >
          Skip
        </button>
        <button
          className="w-full px-3 py-2 text-left hover:bg-accent transition-colors"
          onClick={() => {
            void navigator.clipboard.writeText(JSON.stringify(spec, null, 2));
            onClose();
          }}
        >
          Copy spec JSON
        </button>
        <button
          className="w-full px-3 py-2 text-left hover:bg-accent transition-colors"
          onClick={() => { navigate(`/runs/${runId}/specs/${specId}`); onClose(); }}
        >
          View detail
        </button>
      </div>
    </>
  );
}
