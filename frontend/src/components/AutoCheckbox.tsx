import { useState } from "react";
import { patchAutoConfig } from "@/api/client";

interface Props {
  functionName: string;
  runId: string;
  defaultChecked: boolean;
  label?: string;
}

export function AutoCheckbox({ functionName, runId, defaultChecked, label }: Props) {
  const [checked, setChecked] = useState(defaultChecked);
  const [loading, setLoading] = useState(false);

  async function handleChange(next: boolean) {
    setChecked(next); // optimistic
    setLoading(true);
    try {
      await patchAutoConfig(runId, { [functionName]: next });
    } catch {
      setChecked(!next); // revert on error
    } finally {
      setLoading(false);
    }
  }

  return (
    <label className="flex items-center gap-1.5 cursor-pointer group">
      <input
        type="checkbox"
        checked={checked}
        disabled={loading}
        onChange={(e) => void handleChange(e.target.checked)}
        className="w-3 h-3 accent-primary disabled:opacity-50"
      />
      <span className="text-xs text-muted-foreground group-hover:text-foreground transition-colors">
        {label ?? functionName}
      </span>
    </label>
  );
}
