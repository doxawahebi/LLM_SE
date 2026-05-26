import { useState } from "react";
import type { InterruptPoint } from "@/api/client";

const AVG_TOKENS_PER_SPEC = 5000;
const GEMINI_FLASH_PRICE_PER_M = 0.075;

interface SpecEntry {
  id: string;
  cwe: string;
  file: string;
  line: number;
  func: string;
}

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function SpecSelectorInterrupt({ interrupt, overrides, setOverrides }: Props) {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const specsRaw = (interrupt.option_overrides?.available_specs as SpecEntry[]) ?? [];
  const selectedIds: string[] = Array.isArray(overrides.selected_spec_ids)
    ? (overrides.selected_spec_ids as string[])
    : specsRaw.map((s) => s.id);

  function toggleSpec(id: string) {
    const next = selectedIds.includes(id)
      ? selectedIds.filter((s) => s !== id)
      : [...selectedIds, id];
    setOverrides({ ...overrides, selected_spec_ids: next });
  }

  const filtered = specsRaw.filter(
    (s) =>
      !search ||
      s.cwe.toLowerCase().includes(search.toLowerCase()) ||
      s.file.toLowerCase().includes(search.toLowerCase()) ||
      s.func.toLowerCase().includes(search.toLowerCase())
  );

  const estimatedCostUSD = (
    (selectedIds.length * AVG_TOKENS_PER_SPEC * GEMINI_FLASH_PRICE_PER_M) / 1_000_000
  ).toFixed(2);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          VulnerabilitySpec Selection
        </p>
        <span className="text-xs text-muted-foreground">
          Est. cost: ~${estimatedCostUSD} (Gemini Flash)
        </span>
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Filter specs…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
        />
        <button
          onClick={() => setOverrides({ ...overrides, selected_spec_ids: specsRaw.map((s) => s.id) })}
          className="px-2 py-1 text-xs bg-secondary hover:bg-accent rounded"
        >
          All
        </button>
        <button
          onClick={() => setOverrides({ ...overrides, selected_spec_ids: [] })}
          className="px-2 py-1 text-xs bg-secondary hover:bg-accent rounded"
        >
          None
        </button>
      </div>

      <div className="text-xs text-muted-foreground">
        Selected: {selectedIds.length} / {specsRaw.length}
      </div>

      <div className="max-h-60 overflow-y-auto border border-border rounded divide-y divide-border">
        {filtered.map((s) => {
          const isSelected = selectedIds.includes(s.id);
          const isExpanded = expanded === s.id;
          return (
            <div key={s.id}>
              <div className="flex items-center gap-2 px-2 py-1.5 hover:bg-accent/10 transition-colors">
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => toggleSpec(s.id)}
                  className="w-3 h-3 shrink-0"
                />
                <span className="text-xs text-yellow-300 shrink-0">{s.cwe}</span>
                <span className="flex-1 text-xs text-muted-foreground truncate">
                  {s.file}:{s.line}
                </span>
                <span className="text-xs text-foreground shrink-0">{s.func}</span>
                <button
                  onClick={() => setExpanded(isExpanded ? null : s.id)}
                  className="text-xs text-muted-foreground hover:text-foreground shrink-0"
                >
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>
              {isExpanded && (
                <div className="px-4 py-2 text-xs font-mono text-muted-foreground bg-muted/20">
                  <pre>{JSON.stringify(s, null, 2)}</pre>
                </div>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <p className="text-xs text-muted-foreground p-3 text-center">No specs match filter.</p>
        )}
      </div>

      {selectedIds.length === 0 && (
        <p className="text-xs text-red-400">At least 1 spec must be selected.</p>
      )}
    </div>
  );
}
