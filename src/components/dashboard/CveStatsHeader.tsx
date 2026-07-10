import { AlertOctagon, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useSummary, type SummaryMetric } from "@/hooks/useSummary";

const ICONS: Partial<Record<SummaryMetric["id"], typeof AlertOctagon>> = {
  "critical-cves-30d": AlertOctagon,
  "new-cves-24h": Clock,
};

const CVE_METRIC_IDS: SummaryMetric["id"][] = ["critical-cves-30d", "new-cves-24h"];

/** The two CVE-specific summary stats, moved here from the homepage -- reads the same shared query, no extra fetch. */
export function CveStatsHeader() {
  const { metrics } = useSummary();
  const cveMetrics = metrics.filter((m) => CVE_METRIC_IDS.includes(m.id));

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
      {cveMetrics.map((metric) => {
        const Icon = ICONS[metric.id]!;
        return (
          <Card key={metric.id}>
            <CardHeader>
              <CardTitle>{metric.label}</CardTitle>
              <Icon className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              {metric.isLoading ? (
                <Skeleton className="h-8 w-16" />
              ) : metric.isError ? (
                <span className="text-2xl font-semibold text-critical">—</span>
              ) : (
                <span className="text-2xl font-semibold">{metric.value ?? 0}</span>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
