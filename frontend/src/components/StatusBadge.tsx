import { cn } from "@/lib/cn";
import type { RunStatus, Phase2Status, Phase3Status, Verdict } from "@/lib/types";
import {
  runStatusColor,
  phase2StatusColor,
  phase3StatusColor,
  verdictColor,
} from "@/lib/statusColors";

interface Props {
  type: "run" | "phase2" | "phase3" | "verdict";
  value: RunStatus | Phase2Status | Phase3Status | Verdict;
  className?: string;
}

export function StatusBadge({ type, value, className }: Props) {
  if (value === null) return null;

  let color = "";
  if (type === "run") color = runStatusColor[value as RunStatus];
  else if (type === "phase2") color = phase2StatusColor[value as Phase2Status];
  else if (type === "phase3") color = phase3StatusColor[value as Phase3Status];
  else if (type === "verdict") color = verdictColor[value as NonNullable<Verdict>];

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        color,
        className
      )}
    >
      {value}
    </span>
  );
}
