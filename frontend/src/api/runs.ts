import { apiClient } from "./client";
import type { Run, RunConfig, PaginatedResponse, DashboardMetrics } from "@/lib/types";

export async function listRuns(): Promise<Run[]> {
  const { data } = await apiClient.get<Run[]>("/api/runs");
  return data;
}

export async function getRun(id: string): Promise<Run> {
  const { data } = await apiClient.get<Run>(`/api/runs/${id}`);
  return data;
}

export async function createRun(
  name: string,
  zip: File | undefined,
  config: Partial<RunConfig>
): Promise<{ run_id: string; status: string }> {
  const form = new FormData();
  form.append("name", name);
  if (zip) form.append("project_zip", zip);
  if (config.build_command) form.append("build_command", config.build_command);
  if (config.codeql_build_mode) form.append("codeql_build_mode", config.codeql_build_mode);
  const { data } = await apiClient.post<{ run_id: string; status: string }>("/api/runs", form, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function pauseRun(id: string): Promise<void> {
  await apiClient.post(`/api/runs/${id}/pause`);
}

export async function resumeRun(id: string): Promise<void> {
  await apiClient.post(`/api/runs/${id}/resume`);
}

export async function cancelRun(id: string): Promise<void> {
  await apiClient.post(`/api/runs/${id}/cancel`);
}

export async function cloneRun(id: string): Promise<Run> {
  const { data } = await apiClient.post<Run>(`/api/runs/${id}/clone`);
  return data;
}

export async function deleteRun(id: string): Promise<void> {
  await apiClient.delete(`/api/runs/${id}`);
}

export async function getDashboardMetrics(): Promise<DashboardMetrics> {
  const { data } = await apiClient.get<DashboardMetrics>("/api/metrics");
  return data;
}

export async function rerunFailed(id: string): Promise<void> {
  await apiClient.post(`/api/runs/${id}/rerun-failed`);
}

export async function compareRuns(
  runId: string,
  otherId: string
): Promise<PaginatedResponse<{ run_a: unknown; run_b: unknown }>> {
  const { data } = await apiClient.get(`/api/runs/${runId}/results/compare`, {
    params: { other: otherId },
  });
  return data;
}
