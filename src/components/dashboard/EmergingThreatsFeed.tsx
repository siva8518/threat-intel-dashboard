import { Flame } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { RankedBarChart } from "./RankedBarChart";
import { useEmergingThreatsRanking } from "@/hooks/useEmergingThreatsRanking";

const TOP_N = 10;

function truncateTitle(title: string) {
  return title.length > 28 ? `${title.slice(0, 27)}…` : title;
}

/**
 * Top 10-20 articles across the full ~200-source news pool (not just
 * AI Summarization reports -- those only cover a small daily slice, see
 * server/emergingThreatsRanking.js's header comment), ranked by Threat
 * Priority Score (a transparent weighted heuristic across risk tier, KEV
 * status, peak per-industry risk, and recency). A companion glance to CVE
 * Severity Distribution above it: that widget is CVE-only, this one spans
 * every recent article regardless of whether it names a CVE. Clicking any
 * bar opens the Industry Intelligence tab for the full ranked list, aggregate
 * industry heatmap, and score breakdown (the former standalone "Emerging
 * Threats" tab was absorbed into that page).
 */
export function EmergingThreatsFeed({ onOpenTab }: { onOpenTab: () => void }) {
  const { data, isLoading, isError, error } = useEmergingThreatsRanking();
  const entries = (data?.entries ?? []).slice(0, TOP_N);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Flame className="h-4 w-4 text-primary" />
          Emerging Threats Feed <span className="font-normal text-muted">(top {TOP_N})</span>
        </CardTitle>
        <p className="mt-1 text-xs text-muted">Ranked by Threat Priority Score -- click a bar for the full ranked list and industry heatmap.</p>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-64 w-full" />
        ) : isError || !data ? (
          <ErrorState message={(error as Error)?.message ?? "Emerging Threats Feed is unavailable right now."} />
        ) : entries.length === 0 ? (
          <EmptyState message="No recent articles in the news pool yet -- this feed fills in as sources sync." />
        ) : (
          <RankedBarChart
            hue="#f7913d"
            gradientTo="#fb3f5e"
            data={entries.map((e) => ({
              name: truncateTitle(e.articleTitle),
              count: e.threatPriorityScore.score,
              detail: `${e.articleSource} · ${e.severity}${e.knownExploited ? " · KEV" : ""}`,
              onOpen: onOpenTab,
            }))}
          />
        )}
      </CardContent>
    </Card>
  );
}
