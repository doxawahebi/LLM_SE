import { useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { oneDark } from "@codemirror/theme-one-dark";
import type { InterruptPoint } from "@/api/client";

const ALL_QUERIES = [
  { id: "local/cpp/cwe-120-overflow", cwe: "CWE-120" },
  { id: "local/cpp/cwe-121-stack-overflow", cwe: "CWE-121" },
  { id: "local/cpp/cwe-122-heap-overflow", cwe: "CWE-122" },
  { id: "local/cpp/cwe-123-write-what-where", cwe: "CWE-123" },
  { id: "local/cpp/cwe-124-buffer-underwrite", cwe: "CWE-124" },
  { id: "local/cpp/cwe-125-out-of-bounds-read", cwe: "CWE-125" },
  { id: "local/cpp/cwe-126-buffer-overread", cwe: "CWE-126" },
  { id: "local/cpp/cwe-127-buffer-underread", cwe: "CWE-127" },
  { id: "local/cpp/cwe-190-integer-overflow", cwe: "CWE-190" },
  { id: "local/cpp/cwe-191-integer-underflow", cwe: "CWE-191" },
  { id: "local/cpp/cwe-369-divide-by-zero", cwe: "CWE-369" },
  { id: "local/cpp/cwe-401-memory-leak", cwe: "CWE-401" },
  { id: "local/cpp/cwe-415-double-free", cwe: "CWE-415" },
  { id: "local/cpp/cwe-416-uaf", cwe: "CWE-416" },
  { id: "local/cpp/cwe-457-use-uninitialized", cwe: "CWE-457" },
  { id: "local/cpp/cwe-467-sizeof-pointer", cwe: "CWE-467" },
  { id: "local/cpp/cwe-468-incorrect-ptr-scaling", cwe: "CWE-468" },
  { id: "local/cpp/cwe-469-use-of-pointer-subtraction", cwe: "CWE-469" },
  { id: "local/cpp/cwe-476-null-deref", cwe: "CWE-476" },
  { id: "local/cpp/cwe-570-expression-always-false", cwe: "CWE-570" },
  { id: "local/cpp/cwe-571-expression-always-true", cwe: "CWE-571" },
  { id: "local/cpp/cwe-587-assignment-to-fixed-address", cwe: "CWE-587" },
  { id: "local/cpp/cwe-588-null-ptr-deref-write", cwe: "CWE-588" },
  { id: "local/cpp/cwe-590-free-nonheap-mem", cwe: "CWE-590" },
  { id: "local/cpp/cwe-674-recursion", cwe: "CWE-674" },
  { id: "local/cpp/cwe-688-func-call-with-incorrect-args", cwe: "CWE-688" },
  { id: "local/cpp/cwe-762-mismatched-free", cwe: "CWE-762" },
  { id: "local/cpp/cwe-789-memory-alloc-excessive-size", cwe: "CWE-789" },
  { id: "local/cpp/global/cwe-120-global", cwe: "CWE-120" },
  { id: "local/cpp/global/cwe-122-global", cwe: "CWE-122" },
  { id: "local/cpp/global/cwe-416-global", cwe: "CWE-416" },
  { id: "local/cpp/global/cwe-476-global", cwe: "CWE-476" },
  { id: "local/cpp/flow/dataflow-overflow", cwe: "CWE-120" },
  { id: "local/cpp/flow/taint-uaf", cwe: "CWE-416" },
] as const;

interface Props {
  interrupt: InterruptPoint;
  overrides: Record<string, unknown>;
  setOverrides: (v: Record<string, unknown>) => void;
}

export function QuerySelectorInterrupt({ overrides, setOverrides }: Props) {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [editedQueries, setEditedQueries] = useState<Record<string, string>>({});

  const selectedIds: string[] = Array.isArray(overrides.query_ids)
    ? (overrides.query_ids as string[])
    : ALL_QUERIES.map((q) => q.id);

  function toggleQuery(id: string) {
    const next = selectedIds.includes(id)
      ? selectedIds.filter((q) => q !== id)
      : [...selectedIds, id];
    setOverrides({ ...overrides, query_ids: next });
  }

  function handleEditQuery(id: string, content: string) {
    setEditedQueries((prev) => ({ ...prev, [id]: content }));
    const modified = overrides.modified_queries as Record<string, string> | undefined ?? {};
    setOverrides({ ...overrides, modified_queries: { ...modified, [id]: content } });
  }

  const filtered = ALL_QUERIES.filter(
    (q) =>
      !search ||
      q.id.toLowerCase().includes(search.toLowerCase()) ||
      q.cwe.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Select CodeQL Queries
        </p>
        <span className="text-xs text-muted-foreground ml-auto">
          {selectedIds.length} / {ALL_QUERIES.length} selected
        </span>
      </div>

      <div className="flex gap-2 items-center">
        <input
          type="text"
          placeholder="Search queries…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 px-2 py-1 text-xs bg-secondary border border-border rounded text-foreground"
        />
        <button
          onClick={() => setOverrides({ ...overrides, query_ids: ALL_QUERIES.map((q) => q.id) })}
          className="px-2 py-1 text-xs bg-secondary hover:bg-accent rounded"
        >
          All
        </button>
        <button
          onClick={() => setOverrides({ ...overrides, query_ids: [] })}
          className="px-2 py-1 text-xs bg-secondary hover:bg-accent rounded"
        >
          None
        </button>
      </div>

      <div className="max-h-64 overflow-y-auto border border-border rounded divide-y divide-border">
        {filtered.map((q) => {
          const isSelected = selectedIds.includes(q.id);
          const isExpanded = expanded === q.id;
          const isEdited = q.id in editedQueries;

          return (
            <div key={q.id}>
              <div className="flex items-center gap-2 px-2 py-1.5 hover:bg-accent/10 transition-colors">
                <input
                  type="checkbox"
                  checked={isSelected}
                  onChange={() => toggleQuery(q.id)}
                  className="w-3 h-3 shrink-0"
                />
                <span className="flex-1 text-xs font-mono text-muted-foreground truncate">
                  {q.id}
                </span>
                <span className="text-xs text-yellow-300 shrink-0">{q.cwe}</span>
                {isEdited && <span className="text-xs text-blue-300">*</span>}
                <button
                  onClick={() => setExpanded(isExpanded ? null : q.id)}
                  className="text-xs text-muted-foreground hover:text-foreground shrink-0"
                >
                  {isExpanded ? "▲" : "▼"}
                </button>
              </div>

              {isExpanded && (
                <div className="px-2 pb-2 space-y-1">
                  <div className="border border-border rounded overflow-hidden">
                    <CodeMirror
                      value={editedQueries[q.id] ?? `// Query: ${q.id}\n// CWE: ${q.cwe}\n`}
                      onChange={(val) => handleEditQuery(q.id, val)}
                      theme={oneDark}
                      height="120px"
                      basicSetup={{ lineNumbers: true }}
                    />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {selectedIds.length === 0 && (
        <p className="text-xs text-red-400">At least 1 query must be selected.</p>
      )}
    </div>
  );
}
