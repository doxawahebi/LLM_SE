import { useState } from "react";
import { apiClient } from "@/api/client";

interface Props {
  runId: string;
  specId?: string;
  bulk?: boolean;
}

export function EvidencePackageButton({ runId, specId, bulk = false }: Props) {
  const [loading, setLoading] = useState(false);

  async function handleClick() {
    setLoading(true);
    try {
      const url = bulk
        ? `/api/runs/${runId}/results/evidence-all.tar.gz`
        : `/api/runs/${runId}/specs/${specId}/evidence.tar.gz`;

      const { data } = await apiClient.get<{ url: string }>(url);
      const a = document.createElement("a");
      a.href = data.url;
      a.download = bulk ? "evidence_all.tar.gz" : `evidence_${specId}.tar.gz`;
      a.click();
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={() => void handleClick()}
      disabled={loading}
      className="inline-flex items-center gap-1 px-3 py-1.5 text-xs bg-green-900/30 text-green-300 hover:bg-green-900/50 border border-green-700/30 rounded transition-colors disabled:opacity-50"
    >
      {loading ? "↻ Preparing..." : bulk ? "↓ Export all confirmed bugs" : "↓ Download evidence package"}
    </button>
  );
}
