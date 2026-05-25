import { useState } from "react";
import { apiClient } from "@/api/client";

interface Props {
  runId: string;
  specId?: string;
  phase: 1 | 2 | 3;
  filename: string;
  label: string;
}

export function PhaseDownloadButton({ runId, specId, phase, filename, label }: Props) {
  const [loading, setLoading] = useState(false);

  async function handleClick() {
    setLoading(true);
    try {
      let url: string;
      if (phase === 1) {
        url = `/api/runs/${runId}/phase1/artifacts/${filename}`;
      } else if (specId) {
        url = `/api/runs/${runId}/specs/${specId}/phase${phase}/artifacts/${filename}`;
      } else {
        return;
      }

      const { data } = await apiClient.get<{ url: string }>(url);
      const a = document.createElement("a");
      a.href = data.url;
      a.download = filename;
      a.click();
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={() => void handleClick()}
      disabled={loading}
      className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-secondary hover:bg-accent rounded transition-colors disabled:opacity-50"
    >
      {loading ? "↻" : "↓"} {label}
    </button>
  );
}
