import { apiClient } from "./client";
import type { WorkerStats, LogLine } from "@/lib/types";

export interface Settings {
  default_T_explore: number;
  default_T_author: number;
  default_T_max: number;
  default_T_klee: number;
  default_R_max: number;
  default_parallelism: number;
  llm_providers: LLMProviderConfig[];
  retention_days: number;
}

export interface LLMProviderConfig {
  id: string;
  name: string;
  endpoint: string;
  key_last4: string;
  models: string[];
}

export async function getSettings(): Promise<Settings> {
  const { data } = await apiClient.get<Settings>("/api/settings");
  return data;
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const { data } = await apiClient.patch<Settings>("/api/settings", patch);
  return data;
}

export async function getWorkers(runId: string): Promise<WorkerStats> {
  const { data } = await apiClient.get<WorkerStats>(`/api/runs/${runId}/workers`);
  return data;
}

export interface LogFilters {
  level?: string;
  source?: string;
  spec_id?: string;
  worker_id?: string;
  since?: string;
  limit?: number;
}

export async function getLogs(runId: string, filters: LogFilters = {}): Promise<LogLine[]> {
  const { data } = await apiClient.get<LogLine[]>(`/api/runs/${runId}/logs`, {
    params: filters,
  });
  return data;
}

export async function login(username: string, password: string): Promise<{ access_token: string; refresh_token: string }> {
  const { data } = await apiClient.post("/api/auth/login", { username, password });
  return data;
}

export async function refreshToken(token: string): Promise<{ access_token: string }> {
  const { data } = await apiClient.post("/api/auth/refresh", { refresh_token: token });
  return data;
}

export async function logout(): Promise<void> {
  await apiClient.post("/api/auth/logout");
}
