import { useState } from "react";
import { Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { TimeframeSelector } from "./TimeframeSelector";
import { useAttackTechniques } from "@/hooks/useAttackTechniques";

const TOP_N = 8;

/**
 * MITRE ATT&CK techniques currently observed, derived from malware families
 * in the live threat feed cross-referenced against a curated
 * malware-to-technique map, plus news-derived technique mentions -- see
 * server/correlate.js#computeAttackTechniquesObserved. Best-effort
 * approximation, not live telemetry. Scoped by the timeframe selector below
 * (default 30d, IOCs re-dated by firstSeen and news mentions by their own
 * cached article dates server-side -- see server/lib/dateWindow.js), with an
 * "All" option for full activity-to-date. Clicking a bar opens that
 * technique's MITRE ATT&CK page.
 */
export function TopMitreTechniques() {
  const [days, setDays] = useState<number | null>(30);
  const { data, isLoading, isError } = useAttackTechniques(days);
  const entries = (data ?? []).slice(0, TOP_N);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Radar className="h-4 w-4 text-primary" />
          Top MITRE Techniques
        </CardTitle>
        <TimeframeSelector value={days} onChange={setDays} />
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : isError ? (
          <ErrorState message="Top MITRE Techniques is unavailable right now." />
        ) : entries.length === 0 ? (
          <EmptyState message={days ? `No techniques observed in the live feed in the last ${days} days.` : "No techniques currently observed in the live feed."} />
        ) : (
          <RankedBarChart
            hue="#a855f7"
            data={entries.map((t) => ({
              name: t.id,
              count: t.observedCount ?? 0,
              detail: `${t.name} · ${t.tactic}`,
              onOpen: () => window.open(t.url, "_blank", "noopener,noreferrer"),
            }))}
          />
        )}
      </CardContent>
    </Card>
  );
}
