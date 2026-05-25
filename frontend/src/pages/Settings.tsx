import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getSettings, updateSettings, type Settings } from "@/api/settings";
import { useAuth } from "@/hooks/useAuth";

export function Settings() {
  const can = useAuth((s) => s.can);
  const qc = useQueryClient();

  const { data: settings, isLoading } = useQuery({
    queryKey: ["settings"],
    queryFn: getSettings,
  });

  const { mutate: save } = useMutation({
    mutationFn: (patch: Partial<Settings>) => updateSettings(patch),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (!can("manage_settings")) {
    return (
      <div className="p-6 text-sm text-muted-foreground">
        Settings requires admin role.
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-6 space-y-3">
        {[1, 2, 3].map((i) => <div key={i} className="h-16 bg-muted rounded animate-pulse" />)}
      </div>
    );
  }

  if (!settings) return null;

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <h1 className="text-lg font-bold text-foreground">Settings</h1>

      <Section title="Default Budgets">
        {([
          ["default_T_explore", "T_explore"],
          ["default_T_author", "T_author"],
          ["default_T_max", "T_max"],
          ["default_T_klee", "T_klee (seconds)"],
          ["default_R_max", "R_max"],
          ["default_parallelism", "Parallelism"],
        ] as [keyof Settings, string][]).map(([key, label]) => (
          <Field key={key} label={label}>
            <input
              type="number"
              defaultValue={settings[key] as number}
              onBlur={(e) => save({ [key]: Number(e.target.value) } as Partial<Settings>)}
              className={inputCls}
              min={1}
            />
          </Field>
        ))}
      </Section>

      <Section title="LLM Providers">
        {(settings.llm_providers ?? []).map((p) => (
          <div key={p.id} className="bg-secondary rounded p-3 text-xs">
            <div className="flex justify-between">
              <span className="font-semibold text-foreground">{p.name}</span>
              <span className="text-muted-foreground">···{p.key_last4}</span>
            </div>
            <p className="text-muted-foreground mt-1">{p.endpoint}</p>
            <p className="text-muted-foreground">Models: {p.models.join(", ")}</p>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">
          API keys are write-only. Displayed as last 4 characters only.
        </p>
      </Section>

      <Section title="Retention">
        <Field label="Retention (days)">
          <input
            type="number"
            defaultValue={settings.retention_days}
            onBlur={(e) => save({ retention_days: Number(e.target.value) })}
            className={inputCls}
            min={1}
          />
        </Field>
      </Section>
    </div>
  );
}

const inputCls =
  "w-full px-3 py-2 text-sm bg-muted border border-border rounded text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
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
