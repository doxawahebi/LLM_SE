import { useState } from "react";
import { PhaseDownloadButton } from "./PhaseDownloadButton";
import { apiClient } from "@/api/client";

interface FileEntry {
  filename: string;
  size?: number;
  label?: string;
}

interface Props {
  runId: string;
  specId?: string;
  phase: 1 | 2 | 3;
  files: FileEntry[];
}

export function PhaseDownloadGroup({ runId, specId, phase, files }: Props) {
  const [open, setOpen] = useState(false);
  const [loadingAll, setLoadingAll] = useState(false);

  async function downloadAll() {
    setLoadingAll(true);
    try {
      let url: string;
      if (phase === 1) {
        url = `/api/runs/${runId}/phase1/artifacts.tar.gz`;
      } else if (specId) {
        url = `/api/runs/${runId}/specs/${specId}/phase${phase}/artifacts.tar.gz`;
      } else {
        return;
      }

      const { data } = await apiClient.get<{ url: string }>(url);
      const a = document.createElement("a");
      a.href = data.url;
      a.download = `phase${phase}_outputs.tar.gz`;
      a.click();
    } finally {
      setLoadingAll(false);
    }
  }

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-xs bg-muted/30 hover:bg-accent/20 transition-colors"
      >
        <span className="font-medium text-foreground">Phase {phase} Outputs</span>
        <span className="text-muted-foreground">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="p-2 space-y-1">
          <button
            onClick={() => void downloadAll()}
            disabled={loadingAll}
            className="w-full text-left px-2 py-1 text-xs bg-primary/10 hover:bg-primary/20 rounded transition-colors text-primary disabled:opacity-50"
          >
            {loadingAll ? "Preparing..." : "↓ Download all Phase " + phase + " outputs (.tar.gz)"}
          </button>
          {files.map((f) => (
            <div key={f.filename} className="flex items-center justify-between px-2 py-0.5">
              <span className="text-xs font-mono text-muted-foreground truncate flex-1">
                {f.filename}
                {f.size !== undefined && (
                  <span className="ml-1 text-muted-foreground/50">
                    ({Math.round(f.size / 1024)}KB)
                  </span>
                )}
              </span>
              <PhaseDownloadButton
                runId={runId}
                specId={specId}
                phase={phase}
                filename={f.filename}
                label={f.label ?? f.filename.split(".").pop() ?? ""}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
