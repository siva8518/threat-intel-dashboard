import { Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { useAttackTechniques } from "@/hooks/useAttackTechniques";

const TOP_N = 8;

/** MITRE ATT&CK techniques currently observed, derived from malware families in the live threat feed cross-referenced against a curated malware-to-technique map -- see server/correlate.js#computeAttackTechniquesObserved. Best-effort approximation, not live telemetry. Clicking a bar opens that technique's MITRE ATT&CK page. */
export function TopMitreTechniques() {
  const { data, isLoading, isError } = useAttackTechniques();
  const entries = (data ?? []).slice(0, TOP_N);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Radar className="h-4 w-4 text-primary" />
          Top MITRE Techniques
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : isError ? (
          <ErrorState message="Top MITRE Techniques is unavailable right now." />
        ) : entries.length === 0 ? (
          <EmptyState message="No techniques currently observed in the live feed." />
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
