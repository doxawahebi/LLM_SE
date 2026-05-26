import axios, { type AxiosInstance, type AxiosError } from "axios";
import type { ApiError } from "@/lib/types";
import { showError } from "@/lib/toast";

export interface User {
  id: string;
  username: string;
  email: string;
  role: "viewer" | "operator" | "intervener" | "admin";
  registered_at: string | null;
  last_login_at: string | null;
}

export interface RegisterPayload {
  username: string;
  email: string;
  password: string;
  display_name?: string;
}

export interface RegisterResult {
  user_id: string;
  username: string;
  role: string;
}

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? "";

export const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (r) => r,
  (err: AxiosError) => {
    const status = err.response?.status;
    const data = err.response?.data as Record<string, unknown> | undefined;
    const detail = (data?.detail as string) ?? (data?.message as string) ?? err.message;

    if (status === 401 && !err.config?.url?.includes("/api/auth/login")) {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      window.location.href = "/login";
    } else if (status === 403) {
      showError("Permission denied — you need Operator role or higher to perform this action.")
    } else if (status === 422) {
      showError(`Validation error: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`)
    } else if (status !== undefined && status >= 500) {
      showError(`Server error ${status}: ${detail}`)
    } else if (!err.response) {
      showError("Cannot reach backend. Check that docker compose is running.")
    }

    console.error("[API]", err.config?.url, status, detail)

    const normalized: ApiError = {
      code: (data?.code as string) ?? String(status ?? "network_error"),
      message: detail,
      detail: data,
    };
    return Promise.reject(normalized);
  }
);

export async function register(payload: RegisterPayload): Promise<RegisterResult> {
  const { data } = await apiClient.post<RegisterResult>("/api/auth/register", payload);
  return data;
}

export async function listUsers(): Promise<User[]> {
  const { data } = await apiClient.get<User[]>("/api/users");
  return data;
}

export async function updateUserRole(
  userId: string,
  role: User["role"]
): Promise<void> {
  await apiClient.post(`/api/users/${userId}/role`, { role });
}

export async function deleteUser(userId: string): Promise<void> {
  await apiClient.delete(`/api/users/${userId}`);
}

export async function getAutoConfig(runId: string): Promise<Record<string, boolean>> {
  const { data } = await apiClient.get<Record<string, boolean>>(
    `/api/runs/${runId}/auto-config`
  );
  return data;
}

export async function patchAutoConfig(
  runId: string,
  patch: Record<string, boolean>
): Promise<void> {
  await apiClient.patch(`/api/runs/${runId}/auto-config`, patch);
}

export interface InterruptPoint {
  interrupt_id: string;
  run_id: string;
  spec_id: string | null;
  function_name: string;
  phase: 1 | 2 | 3;
  turn: number | null;
  status: "waiting" | "resumed" | "skipped";
  created_at: string;
  input_files: Array<{ name: string; size: number; content_type: string; artifact_url: string }>;
  option_overrides: Record<string, unknown>;
}

export async function listInterrupts(runId: string): Promise<InterruptPoint[]> {
  const { data } = await apiClient.get<InterruptPoint[]>(
    `/api/runs/${runId}/interrupts`
  );
  return data;
}

export async function getInterrupt(
  runId: string,
  interruptId: string
): Promise<InterruptPoint> {
  const { data } = await apiClient.get<InterruptPoint>(
    `/api/runs/${runId}/interrupts/${interruptId}`
  );
  return data;
}

export interface ResumePayload {
  modified_files?: Array<{ name: string; content_base64: string }>;
  option_overrides?: Record<string, unknown>;
}

export async function resumeInterrupt(
  runId: string,
  interruptId: string,
  payload: ResumePayload
): Promise<void> {
  await apiClient.post(
    `/api/runs/${runId}/interrupts/${interruptId}/resume`,
    payload
  );
}

export async function skipInterrupt(
  runId: string,
  interruptId: string
): Promise<void> {
  await apiClient.post(`/api/runs/${runId}/interrupts/${interruptId}/skip`);
}

export interface ValidationResult {
  valid: boolean;
  severity: "error" | "warning" | "info";
  message: string;
  detected_format: string;
}

export async function validateFile(
  filename: string,
  contentBase64: string
): Promise<ValidationResult> {
  const { data } = await apiClient.post<ValidationResult>("/api/validate/file", {
    filename,
    content_base64: contentBase64,
  });
  return data;
}
