import { cn } from "@/lib/cn";

interface Props {
  value: number;  // 0-100
  label?: string;
  color?: string;
  className?: string;
  showPercent?: boolean;
}

export function ProgressBar({
  value,
  label,
  color = "bg-blue-500",
  className,
  showPercent = false,
}: Props) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <div className={cn("flex items-center gap-2", className)}>
      {label && <span className="text-xs text-muted-foreground w-16 shrink-0">{label}</span>}
      <div className="flex-1 bg-secondary rounded-full h-2 overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all duration-300", color)}
          style={{ width: `${clamped}%` }}
        />
      </div>
      {showPercent && (
        <span className="text-xs text-muted-foreground w-10 text-right">
          {Math.round(clamped)}%
        </span>
      )}
    </div>
  );
}
