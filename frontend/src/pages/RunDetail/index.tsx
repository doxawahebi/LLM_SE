import { useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getRun } from "@/api/runs";
import { listSpecs } from "@/api/specs";
import { useRunStore } from "@/hooks/useRunStore";
import { useSpecStore } from "@/hooks/useSpecStore";
import { useSSE, type InterruptNotification } from "@/hooks/useSSE";
import { RunHeader } from "./RunHeader";
import { SpecTable } from "./SpecTable";
import { ChartsStrip } from "./ChartsStrip";
import { RunResultsTab } from "./RunResultsTab";
import { PipelineControlsSidebar } from "@/components/PipelineControlsSidebar";
import { SSEStatusIndicator } from "@/components/SSEStatusIndicator";
import { cn } from "@/lib/cn";

type Tab = "specs" | "charts" | "results" | "logs" | "workers";

export function RunDetail() {
  const { run_id } = useParams<{ run_id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<Tab>("specs");

  const setRun = useRunStore((s) => s.setRun);
  const setSpecs = useSpecStore((s) => s.setSpecs);
  const run = useRunStore((s) => s.runs.get(run_id ?? ""));
  const [interruptToast, setInterruptToast] = useState<InterruptNotification | null>(null);
  const [sseConnected, setSseConnected] = useState(false);

  const handleInterrupt = useCallback((evt: InterruptNotification) => {
    setInterruptToast(evt);
    // auto-dismiss after 8s
    setTimeout(() => setInterruptToast(null), 8000);
  }, []);

  const handleSseConnect = useCallback(() => setSseConnected(true), []);
  const handleSseDisconnect = useCallback(() => setSseConnected(false), []);
  const sseTopics = run_id ? [`runs.${run_id}`, `runs.${run_id}.specs`] : [];

  useSSE({
    topics: sseTopics,
    enabled: !!run_id,
    onInterrupt: handleInterrupt,
    onConnect: handleSseConnect,
    onDisconnect: handleSseDisconnect,
  });

  useQuery({
    queryKey: ["run", run_id],
    queryFn: async () => {
      if (!run_id) return null;
      const r = await getRun(run_id);
      setRun(r);
      return r;
    },
    enabled: !!run_id,
  });

  useQuery({
    queryKey: ["specs", run_id],
    queryFn: async () => {
      if (!run_id) return [];
      const page = await listSpecs(run_id, { limit: 5000 });
      setSpecs(page.items);
      return page;
    },
    enabled: !!run_id,
    refetchInterval: 15_000,
  });

  if (!run) {
    return (
      <div className="p-6">
        <div className="h-32 bg-card border border-border rounded-lg animate-pulse" />
      </div>
    );
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: "specs", label: "Specs" },
    { key: "charts", label: "Charts" },
    { key: "results", label: "Results" },
    { key: "logs", label: "Logs" },
    { key: "workers", label: "Workers" },
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto relative">
      {/* Interrupt toast */}
      {interruptToast && (
        <div className="fixed bottom-4 right-4 z-50 bg-yellow-900/90 border border-yellow-700/50 text-yellow-200 rounded-lg shadow-xl px-4 py-3 text-sm max-w-sm">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="font-semibold">⏸ Pipeline paused</p>
              <p className="text-xs mt-0.5 text-yellow-300/80">
                {interruptToast.function_name}
                {interruptToast.spec_id && ` · Spec ${interruptToast.spec_id.slice(-6)}`}
              </p>
            </div>
            <div className="flex gap-2 items-start shrink-0">
              {interruptToast.spec_id && (
                <button
                  onClick={() => {
                    navigate(`/runs/${interruptToast.run_id}/specs/${interruptToast.spec_id}`);
                    setInterruptToast(null);
                  }}
                  className="text-xs text-yellow-200 hover:text-white underline"
                >
                  Go to spec →
                </button>
              )}
              <button
                onClick={() => setInterruptToast(null)}
                className="text-yellow-300/60 hover:text-yellow-200"
              >
                ✕
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Pipeline controls sidebar */}
      <PipelineControlsSidebar runId={run_id ?? ""} />
      <div className="flex items-center justify-between gap-2 mb-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <button onClick={() => navigate("/")} className="hover:text-foreground transition-colors">
            Runs
          </button>
          <span>/</span>
          <span className="text-foreground">{run.name}</span>
        </div>
        <SSEStatusIndicator connected={sseConnected} />
      </div>

      <RunHeader run={run} />

      <div className="flex gap-1 mb-4 border-b border-border">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => {
              if (t.key === "logs") navigate(`/runs/${run_id}/logs`);
              else if (t.key === "workers") navigate(`/runs/${run_id}/workers`);
              else setActiveTab(t.key);
            }}
            className={cn(
              "px-4 py-2 text-xs transition-colors",
              activeTab === t.key
                ? "text-foreground border-b-2 border-primary"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === "specs" && <SpecTable runId={run_id ?? ""} />}
      {activeTab === "charts" && <ChartsStrip run={run} />}
      {activeTab === "results" && <RunResultsTab runId={run_id ?? ""} />}
    </div>
  );
}
