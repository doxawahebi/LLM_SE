interface Props {
  severity: "error" | "warning" | "info";
  message: string;
  detectedFormat?: string;
}

const CONFIG = {
  error: {
    bg: "bg-red-900/20 border-red-700/40",
    icon: "✖",
    text: "text-red-300",
    label: "Error",
  },
  warning: {
    bg: "bg-yellow-900/20 border-yellow-700/40",
    icon: "⚠",
    text: "text-yellow-300",
    label: "Warning",
  },
  info: {
    bg: "bg-blue-900/20 border-blue-700/40",
    icon: "ℹ",
    text: "text-blue-300",
    label: "Info",
  },
} as const;

export function FileValidationBanner({ severity, message, detectedFormat }: Props) {
  const cfg = CONFIG[severity];
  return (
    <div className={`border rounded p-2 text-xs ${cfg.bg} ${cfg.text}`}>
      <span className="font-semibold">{cfg.icon} {cfg.label}:</span>{" "}
      {message}
      {detectedFormat && (
        <span className="ml-1 text-muted-foreground">
          (detected: {detectedFormat})
        </span>
      )}
    </div>
  );
}
