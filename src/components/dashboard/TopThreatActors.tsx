import { Skull } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { useThreatActors } from "@/hooks/useRansomware";

const TOP_N = 8;

interface TopThreatActorsProps {
  onNavigateToActors: () => void;
}

/**
 * All-time (not "same calendar day") merged actor activity -- see
 * server/correlate.js#mergeThreatActors, ransomware.live victim posts + OTX
 * pulse "adversary" tags. Deliberately not scoped to today: a same-day
 * leaderboard resets to empty at midnight UTC, which made that version of
 * this widget show "no activity" more often than real data. This one is
 * activity-to-date, so it's essentially never empty.
 */
export function TopThreatActors({ onNavigateToActors }: TopThreatActorsProps) {
  const { data, isLoading, isError } = useThreatActors();
  const actors = (data ?? []).slice().sort((a, b) => b.campaignCount - a.campaignCount).slice(0, TOP_N);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Skull className="h-4 w-4 text-primary" />
          Top Threat Actors
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : isError ? (
          <ErrorState message="Top Threat Actors is unavailable right now." />
        ) : actors.length === 0 ? (
          <EmptyState message="No ransomware or OTX pulse actor activity recorded yet." />
        ) : (
          <RankedBarChart
            hue="#fb3f5e"
            data={actors.map((a) => ({
              name: a.name,
              count: a.campaignCount,
              detail: `${a.type === "ransomware" ? "Ransomware group" : "OTX-tagged actor"} · last active ${new Date(a.lastActivity).toLocaleDateString()}`,
              onOpen: onNavigateToActors,
            }))}
          />
        )}
      </CardContent>
    </Card>
  );
}
