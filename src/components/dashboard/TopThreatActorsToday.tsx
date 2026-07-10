import { Minus, Skull, TrendingDown, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useTopThreatActorsToday } from "@/hooks/useTopThreatActorsToday";
import type { ActorTrend, TopThreatActor } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const TREND_STYLE: Record<ActorTrend, { icon: typeof TrendingUp; color: string; label: string }> = {
  up: { icon: TrendingUp, color: "text-critical", label: "Rising vs. yesterday" },
  down: { icon: TrendingDown, color: "text-low", label: "Falling vs. yesterday" },
  steady: { icon: Minus, color: "text-muted", label: "Unchanged vs. yesterday" },
};

function ActorRow({ actor, onClick }: { actor: TopThreatActor; onClick: () => void }) {
  const trend = TREND_STYLE[actor.trend];
  const TrendIcon = trend.icon;
  return (
    <li>
      <button
        type="button"
        onClick={onClick}
        title={`View ${actor.name} in Threat Actors & Tools`}
        className="flex w-full items-center gap-3 rounded-lg px-1.5 py-2 text-left transition-colors hover:bg-white/[0.05]"
      >
        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/[0.03] text-xs font-semibold text-muted">
          {actor.rank}
        </span>
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-foreground">{actor.name}</span>
        <span className="shrink-0 text-xs tabular-nums text-muted">{actor.score}</span>
        <span title={trend.label}>
          <TrendIcon className={cn("h-4 w-4 shrink-0", trend.color)} aria-label={trend.label} />
        </span>
      </button>
    </li>
  );
}

interface TopThreatActorsTodayProps {
  onNavigateToActors: () => void;
}

/** Same-calendar-day ranked actor leaderboard -- see server/topThreatActorsToday.js. */
export function TopThreatActorsToday({ onNavigateToActors }: TopThreatActorsTodayProps) {
  const { actors, isLoading, isError, error } = useTopThreatActorsToday();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Skull className="h-4 w-4 text-primary" />
          Top Threat Actors Today
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={error?.message ?? "Top Threat Actors Today is unavailable right now."} />
        ) : actors.length === 0 ? (
          <EmptyState message="No ransomware, OTX pulse, or news-tagged threat actor activity recorded yet today." />
        ) : (
          <ul className="divide-y divide-white/[0.06]">
            {actors.map((actor) => (
              <ActorRow key={actor.rank} actor={actor} onClick={onNavigateToActors} />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
