import { useState, useCallback, type DragEvent, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { createRun, getRun } from "@/api/runs";
import type { RunConfig } from "@/lib/types";

const DEFAULT_CONFIG: Partial<RunConfig> = {
  T_explore: 8,
  T_author: 12,
  T_max: 60,
  T_klee: 300,
  R_max: 15,
  parallelism: 128,
  codeql_build_mode: "autodetect",
  run_phase3: true,
  llm_provider: "gemini",
  llm_model: "gemini-2.0-flash",
};

export function NewRun() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const cloneId = searchParams.get("clone");

  const [name, setName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [config, setConfig] = useState<Partial<RunConfig>>(DEFAULT_CONFIG);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useQuery({
    queryKey: ["run", cloneId],
    queryFn: async () => {
      if (!cloneId) return null;
      const run = await getRun(cloneId);
      setName(`${run.name} (copy)`);
      setConfig(run.config);
      return run;
    },
    enabled: !!cloneId,
  });

  const onDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f?.name.endsWith(".zip")) setFile(f);
    else setError("Please upload a .zip file");
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setError("Please enter a project name"); return; }
    if (!file) {
      setError(
        "A project .zip file is required to start the pipeline. " +
        "Drag and drop your source archive or click 'or browse'."
      );
      return;
    }
    setLoading(true);
    setError("");
    try {
      const run = await createRun(name, file, config);
      navigate(`/runs/${run.run_id}`);
    } catch (err: unknown) {
      const apiErr = err as { message?: string; code?: string };
      if (apiErr.code === "403" || apiErr.message?.toLowerCase().includes("role")) {
        setError(
          "You need Operator role to create runs. Ask an admin to update your role at Settings → Users."
        );
      } else {
        setError(apiErr.message ?? "Failed to create run");
      }
      console.error("[NewRun] createRun failed:", err);
    } finally {
      setLoading(false);
    }
  }

  function updateConfig<K extends keyof RunConfig>(key: K, value: RunConfig[K]) {
    setConfig((c) => ({ ...c, [key]: value }));
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <h1 className="text-lg font-bold text-foreground mb-6">
        {cloneId ? "Clone Run" : "New Run"}
      </h1>

      <form onSubmit={(e) => void handleSubmit(e)} className="space-y-6">
        {error && (
          <div className="p-3 bg-red-950/60 border border-red-700/50 rounded-lg text-sm text-red-400">
            {error}
          </div>
        )}

        <Section title="Project">
          <Field label="Name">
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="my-project"
              className={inputCls}
              required
            />
          </Field>

          <Field label="Source zip">
            <div
              onDrop={onDrop}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              className={`border-2 border-dashed rounded p-6 text-center text-sm transition-colors ${
                dragging ? "border-primary bg-primary/5" : "border-border"
              }`}
            >
              {file ? (
                <p className="text-foreground">{file.name}</p>
              ) : (
                <>
                  <p className="text-muted-foreground mb-2">
                    Drag and drop a .zip file here
                  </p>
                  <label className="cursor-pointer text-primary underline">
                    or browse
                    <input
                      type="file"
                      accept=".zip"
                      className="hidden"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) setFile(f);
                      }}
                    />
                  </label>
                </>
              )}
            </div>
          </Field>

          <Field label="Build command">
            <input
              type="text"
              value={config.build_command ?? ""}
              onChange={(e) => updateConfig("build_command", e.target.value || null)}
              placeholder="(autodetect)"
              className={inputCls}
            />
          </Field>

          <Field label="CodeQL build mode">
            <select
              value={config.codeql_build_mode ?? "autodetect"}
              onChange={(e) => updateConfig("codeql_build_mode", e.target.value as RunConfig["codeql_build_mode"])}
              className={inputCls}
            >
              <option value="autodetect">autodetect</option>
              <option value="none">none</option>
              <option value="custom">custom</option>
            </select>
          </Field>
        </Section>

        <Section title="Phase 2 Budgets">
          {([
            ["T_explore", "T_explore (exploration turns)"],
            ["T_author", "T_author (authoring turns)"],
            ["T_max", "T_max (total turn budget)"],
            ["T_klee", "T_klee (KLEE timeout, seconds)"],
            ["R_max", "R_max (max refinements)"],
            ["parallelism", "Parallelism (concurrent specs)"],
          ] as [keyof RunConfig, string][]).map(([key, label]) => (
            <Field key={key} label={label}>
              <input
                type="number"
                value={config[key] as number ?? 0}
                onChange={(e) => updateConfig(key, Number(e.target.value) as RunConfig[typeof key])}
                className={inputCls}
                min={1}
              />
            </Field>
          ))}
        </Section>

        <Section title="Phase 3">
          <Field label="Run concrete validation">
            <input
              type="checkbox"
              checked={config.run_phase3 ?? true}
              onChange={(e) => updateConfig("run_phase3", e.target.checked)}
              className="w-4 h-4"
            />
          </Field>
        </Section>

        <div className="flex gap-3">
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2 text-sm bg-primary text-primary-foreground rounded hover:bg-primary/80 transition-colors disabled:opacity-50"
          >
            {loading ? "Starting..." : "Start Run"}
          </button>
          <button
            type="button"
            onClick={() => navigate(-1)}
            className="px-6 py-2 text-sm bg-secondary text-foreground rounded hover:bg-accent transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

const inputCls =
  "w-full px-3 py-2 text-sm bg-secondary border border-border rounded text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
        {title}
      </h2>
      <div className="bg-card border border-border rounded-lg p-4 space-y-3">
        {children}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-4 items-center">
      <label className="text-xs text-muted-foreground">{label}</label>
      <div className="col-span-2">{children}</div>
    </div>
  );
}
