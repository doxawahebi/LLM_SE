// Frontend-only types that never appear in network payloads.
// Wire types live in @/shared/contracts/sailor.types.

export type FilterPreset = { name: string; filters: SpecFilters };

export type SpecFilters = {
  phase?: 1 | 2 | 3;
  status?: string;
  cwe?: string;
  fileGlob?: string;
  verdict?: string;
  search?: string;
};

export type ToastSeverity = "info" | "success" | "warning" | "error";
