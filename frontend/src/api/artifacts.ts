import { apiClient } from "./client";
import type { ArtifactNode } from "@/lib/types";

export async function getArtifactTree(
  runId: string,
  specId: string
): Promise<ArtifactNode[]> {
  const { data } = await apiClient.get<ArtifactNode[]>(
    `/api/runs/${runId}/specs/${specId}/artifacts`
  );
  return data;
}

export async function getArtifactUrl(
  runId: string,
  specId: string,
  path: string
): Promise<string> {
  const { data } = await apiClient.get<{ url: string }>(
    `/api/runs/${runId}/specs/${specId}/artifacts/${encodeURIComponent(path)}`
  );
  return data.url;
}

export async function exportArtifacts(
  runId: string,
  specId: string
): Promise<string> {
  const { data } = await apiClient.post<{ job_id: string }>(
    `/api/runs/${runId}/specs/${specId}/artifacts/export`
  );
  return data.job_id;
}

export async function exportResults(runId: string): Promise<string> {
  const { data } = await apiClient.post<{ job_id: string }>(
    `/api/runs/${runId}/results/export`
  );
  return data.job_id;
}
