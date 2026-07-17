import { useState } from "react";
import { Skull } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { TimeframeSelector } from "./TimeframeSelector";
import { useThreatActors } from "@/hooks/useRansomware";
import type { ThreatActor } from "@/types/threat-intel";

const TOP_N = 8;

interface TopThreatActorsProps {
  /** Deep-links a clicked actor's name into Threat Actor Intelligence's own search, not a fixed tab -- each bar can represent a ransomware group, an OTX-tagged actor, or a news-tracked APT/cybercrime actor with no ransomware.live record at all, so a single fixed destination (previously always "Ransomware Data") showed nothing for most of them. */
  onSelectActor: (name: string) => void;
}

/**
 * Label for the source/type of one merged actor entry -- "ransomware" and
 * "otx-tagged" are provenance tags for the two original bulk sources; any
 * other value is a real ThreatActorType classification (APT, Cybercrime,
 * etc.) for an actor sourced purely from automated news extraction (see
 * server/threatActorIntelligence.js) with no ransomware.live/OTX record.
 */
function typeLabel(type: ThreatActor["type"]): string {
  if (type === "ransomware") return "Ransomware group";
  if (type === "otx-tagged") return "OTX-tagged actor";
  return `${type} (news-tracked)`;
}

/**
 * Merged actor activity -- see server/correlate.js#mergeThreatActors,
 * ransomware.live victim posts + OTX pulse "adversary" tags + threat-actor
 * mentions automatically extracted from news article text across every
 * configured source. Scoped by the timeframe selector below (default 30d,
 * re-derived server-side from each source's own dated records -- see
 * server/lib/dateWindow.js -- not a client-side filter over an all-time
 * list), with an "All" option for full activity-to-date.
 */
export function TopThreatActors({ onSelectActor }: TopThreatActorsProps) {
  const [days, setDays] = useState<number | null>(30);
  const { data, isLoading, isError } = useThreatActors(days);
  const actors = (data ?? []).slice().sort((a, b) => b.campaignCount - a.campaignCount).slice(0, TOP_N);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Skull className="h-4 w-4 text-primary" />
          Top Threat Actors
        </CardTitle>
        <TimeframeSelector value={days} onChange={setDays} />
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : isError ? (
          <ErrorState message="Top Threat Actors is unavailable right now." />
        ) : actors.length === 0 ? (
          <EmptyState message={days ? `No ransomware, OTX pulse, or news-derived actor activity in the last ${days} days.` : "No ransomware, OTX pulse, or news-derived actor activity recorded yet."} />
        ) : (
          <RankedBarChart
            hue="#fb3f5e"
            data={actors.map((a) => ({
              name: a.name,
              count: a.campaignCount,
              detail: `${typeLabel(a.type)} · last active ${new Date(a.lastActivity).toLocaleDateString()}`,
              onOpen: () => onSelectActor(a.name),
            }))}
          />
        )}
      </CardContent>
    </Card>
  );
}
