import { Flame, TrendingDown, TrendingUp, Minus } from "lucide-react";
import { Bar, BarChart, ResponsiveContainer, Tooltip } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useExecutiveSummary } from "@/hooks/useExecutiveSummary";
import type { ThreatScoreSnapshot } from "@/types/threat-intel";

const WINDOW_DAYS = 7;

function ChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: ThreatScoreSnapshot }> }) {
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0].payload;
  return (
    <div className="rounded-lg border border-white/10 bg-surface px-2.5 py-1.5 text-xs shadow-glass">
      <p className="font-mono font-semibold text-foreground">{point.date}</p>
      <p className="text-muted">
        Campaigns <span className="text-foreground">{point.totalActiveCampaigns}</span>
      </p>
    </div>
  );
}

/** Lighter companion to ThreatScoreTrend.tsx -- a plain week-over-week comparison of total active-campaign volume (same field ExecutiveThreatSummary's "Total Active Campaigns" fact card shows), reusing the same daily history rather than a full second score line. */
export function CampaignVolumeTrend() {
  const { data, isLoading, isError } = useExecutiveSummary();
  const history = data?.scoreHistory ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Flame className="h-4 w-4 text-primary" />
          Weekly Campaign Volume
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : isError || !data ? (
          <ErrorState message="Weekly Campaign Volume is unavailable right now." />
        ) : history.length < 2 ? (
          <EmptyState message="Collecting daily history -- check back tomorrow for a trend." />
        ) : (
          <VolumeBody history={history} />
        )}
      </CardContent>
    </Card>
  );
}

function VolumeBody({ history }: { history: ThreatScoreSnapshot[] }) {
  const thisWeek = history.slice(-WINDOW_DAYS);
  const priorWeek = history.slice(-WINDOW_DAYS * 2, -WINDOW_DAYS);

  const thisWeekTotal = thisWeek.reduce((sum, s) => sum + s.totalActiveCampaigns, 0);
  const hasPriorWeek = priorWeek.length > 0;
  const priorWeekTotal = priorWeek.reduce((sum, s) => sum + s.totalActiveCampaigns, 0);
  const pctChange = hasPriorWeek && priorWeekTotal > 0 ? Math.round(((thisWeekTotal - priorWeekTotal) / priorWeekTotal) * 100) : null;

  const DeltaIcon = pctChange === null || pctChange === 0 ? Minus : pctChange > 0 ? TrendingUp : TrendingDown;
  const deltaColor = pctChange === null || pctChange === 0 ? "text-muted" : pctChange > 0 ? "text-critical" : "text-low";

  return (
    <>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-2xl font-bold tabular-nums text-foreground">{thisWeekTotal}</span>
        <span className={`flex items-center gap-1 text-xs font-medium ${deltaColor}`}>
          <DeltaIcon className="h-3.5 w-3.5" />
          {pctChange === null ? "no prior week yet" : `${pctChange > 0 ? "+" : ""}${pctChange}% vs prior week`}
        </span>
      </div>
      <p className="mb-2 text-xs text-muted">Active campaigns, last {thisWeek.length} day{thisWeek.length === 1 ? "" : "s"}</p>
      <ResponsiveContainer width="100%" height={72}>
        <BarChart data={history.slice(-14)} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
          <Bar dataKey="totalActiveCampaigns" fill="#a855f7" radius={[3, 3, 0, 0]} maxBarSize={16} />
        </BarChart>
      </ResponsiveContainer>
    </>
  );
}
