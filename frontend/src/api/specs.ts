import { apiClient } from "./client";
import type { Spec, Turn, PaginatedResponse, VerifiedBug } from "@/lib/types";

export interface SpecFilters {
  phase?: string;
  status?: string;
  cwe?: string;
  file?: string;
  verdict?: string;
  search?: string;
  cursor?: string;
  limit?: number;
}

export async function listSpecs(
  runId: string,
  filters: SpecFilters = {}
): Promise<PaginatedResponse<Spec>> {
  const { data } = await apiClient.get<PaginatedResponse<Spec>>(
    `/api/runs/${runId}/specs`,
    { params: filters }
  );
  return data;
}

export async function getSpec(runId: string, specId: string): Promise<Spec> {
  const { data } = await apiClient.get<Spec>(`/api/runs/${runId}/specs/${specId}`);
  return data;
}

export async function listTurns(
  runId: string,
  specId: string
): Promise<Turn[]> {
  const { data } = await apiClient.get<Turn[]>(
    `/api/runs/${runId}/specs/${specId}/turns`
  );
  return data;
}

export async function getTurn(
  runId: string,
  specId: string,
  turnId: string
): Promise<Turn> {
  const { data } = await apiClient.get<Turn>(
    `/api/runs/${runId}/specs/${specId}/turns/${turnId}`
  );
  return data;
}

export async function requeueSpec(runId: string, specId: string): Promise<void> {
  await apiClient.post(`/api/runs/${runId}/specs/${specId}/requeue`);
}

export async function skipSpec(runId: string, specId: string): Promise<void> {
  await apiClient.post(`/api/runs/${runId}/specs/${specId}/skip`);
}

export async function bulkRequeue(runId: string, specIds: string[]): Promise<void> {
  await apiClient.post(`/api/runs/${runId}/specs/bulk-requeue`, { spec_ids: specIds });
}

export async function bulkSkip(runId: string, specIds: string[]): Promise<void> {
  await apiClient.post(`/api/runs/${runId}/specs/bulk-skip`, { spec_ids: specIds });
}

export interface InterventionPayload {
  mode: "edit_harness" | "force_outcome" | "edit_spec";
  file?: string;
  content?: string;
  base_version?: number;
  outcome?: string;
  ktest_path?: string;
  spec_json?: string;
}

export async function intervene(
  runId: string,
  specId: string,
  payload: InterventionPayload
): Promise<void> {
  await apiClient.post(`/api/runs/${runId}/specs/${specId}/intervene`, payload);
}

export async function getResults(runId: string): Promise<VerifiedBug[]> {
  const { data } = await apiClient.get<VerifiedBug[]>(`/api/runs/${runId}/results`);
  return data;
}
