import { cn } from "@/lib/utils";

const TIMEFRAMES: Array<{ label: string; days: number | null }> = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "All", days: null },
];

interface TimeframeSelectorProps {
  value: number | null;
  onChange: (days: number | null) => void;
  className?: string;
}

/**
 * Compact button-group timeframe filter shared by Top Threat Actors/CVEs/
 * MITRE Techniques. Selecting a window re-derives each ranking server-side
 * from only that window's activity (see server/lib/dateWindow.js) -- not a
 * client-side filter over an already-computed all-time list, so counts
 * genuinely reflect the selected timeframe.
 */
export function TimeframeSelector({ value, onChange, className }: TimeframeSelectorProps) {
  return (
    <div className={cn("flex shrink-0 gap-1", className)}>
      {TIMEFRAMES.map((tf) => (
        <button
          key={tf.label}
          type="button"
          onClick={() => onChange(tf.days)}
          className={cn(
            "rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors",
            value === tf.days ? "bg-gradient-primary text-white" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
          )}
        >
          {tf.label}
        </button>
      ))}
    </div>
  );
}
