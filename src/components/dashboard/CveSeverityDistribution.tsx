import { ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useCveSeverityDistribution } from "@/hooks/useCveSeverityDistribution";
import type { Severity } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

// Reuses the app's existing semantic severity colors (same ones SeverityBadge
// and the ATT&CK Tactic Heat Map already use) -- severity is a status
// encoding, not a categorical one, so it draws from that reserved palette
// rather than a generated hue.
const SEGMENTS: Array<{ key: keyof CveCounts; label: string; severity: Severity; color: string }> = [
  { key: "critical", label: "Critical", severity: "CRITICAL", color: "#fb3f5e" },
  { key: "high", label: "High", severity: "HIGH", color: "#f7913d" },
  { key: "medium", label: "Medium", severity: "MEDIUM", color: "#f2c94c" },
  { key: "low", label: "Low", severity: "LOW", color: "#2fd97c" },
];

interface CveCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface CveSeverityDistributionProps {
  onSelectSeverity: (severity: Severity) => void;
}

/** Part-to-whole horizontal stacked bar -- see server/connectors/nvd.js's per-severity 30-day counts. Segment widths are percentage-based, so this always fills its card regardless of column width. Each segment jumps to Latest CVEs pre-filtered by that severity. */
export function CveSeverityDistribution({ onSelectSeverity }: CveSeverityDistributionProps) {
  const { data, isLoading, isError } = useCveSeverityDistribution();
  const total = data ? data.critical + data.high + data.medium + data.low : 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <ShieldAlert className="h-4 w-4 text-primary" />
          CVE Severity Distribution <span className="font-normal text-muted">(last 30 days)</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading || (data && !data.ready) ? (
          <Skeleton className="h-16 w-full" />
        ) : isError || !data ? (
          <ErrorState message="CVE Severity Distribution is unavailable right now." />
        ) : total === 0 ? (
          <EmptyState message="No CVEs published in the last 30 days." />
        ) : (
          <>
            <div className="flex h-8 w-full gap-0.5 overflow-hidden rounded-lg">
              {SEGMENTS.filter((s) => data[s.key] > 0).map((s, i, arr) => {
                const share = data[s.key] / total;
                return (
                  <button
                    key={s.key}
                    type="button"
                    onClick={() => onSelectSeverity(s.severity)}
                    title={`${s.label}: ${data[s.key]} -- click to view in Latest CVEs`}
                    style={{ width: `${share * 100}%`, backgroundColor: s.color }}
                    className={cn(
                      "flex items-center justify-center text-xs font-semibold text-black/70 transition-opacity hover:opacity-85",
                      i === 0 && "rounded-l-lg",
                      i === arr.length - 1 && "rounded-r-lg",
                    )}
                  >
                    {share > 0.12 && data[s.key]}
                  </button>
                );
              })}
            </div>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">
              {SEGMENTS.map((s) => (
                <button
                  key={s.key}
                  type="button"
                  onClick={() => onSelectSeverity(s.severity)}
                  className="flex items-center gap-1.5 text-xs text-muted transition-colors hover:text-foreground"
                >
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: s.color }} />
                  {s.label} <span className="font-semibold text-foreground">{data[s.key]}</span>
                </button>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
