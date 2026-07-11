import { TrendingDown, TrendingUp, Minus, Activity } from "lucide-react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useExecutiveSummary } from "@/hooks/useExecutiveSummary";
import type { ThreatScoreSnapshot } from "@/types/threat-intel";

// Same four-tier palette as ExecutiveThreatSummary's LEVEL_STYLE -- the trend
// line's color should read as the same "how worried should I be" signal as
// the score gauge it's tracking, not an arbitrary chart hue.
function colorForScore(score: number) {
  if (score <= 25) return "#2fd97c";
  if (score <= 50) return "#f2c94c";
  if (score <= 75) return "#f7913d";
  return "#fb3f5e";
}

function ChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: ThreatScoreSnapshot }> }) {
  if (!active || !payload || payload.length === 0) return null;
  const point = payload[0].payload;
  return (
    <div className="rounded-lg border border-white/10 bg-surface px-2.5 py-1.5 text-xs shadow-glass">
      <p className="font-mono font-semibold text-foreground">{point.date}</p>
      <p className="text-muted">
        Score <span className="text-foreground">{point.score}</span>
      </p>
    </div>
  );
}

/** Rolling daily line of the Executive Threat Summary score -- see server/threatScoreHistory.js. Turns the single score snapshot into a real trajectory (rising/falling), the one thing a board-level view needs that a point-in-time gauge can't say. */
export function ThreatScoreTrend() {
  const { data, isLoading, isError } = useExecutiveSummary();
  const history = data?.scoreHistory ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Activity className="h-4 w-4 text-primary" />
          Threat Level Trend
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : isError || !data ? (
          <ErrorState message="Threat Level Trend is unavailable right now." />
        ) : history.length < 2 ? (
          <EmptyState message="Collecting daily history -- check back tomorrow for a trend line." />
        ) : (
          <TrendBody history={history} />
        )}
      </CardContent>
    </Card>
  );
}

function TrendBody({ history }: { history: ThreatScoreSnapshot[] }) {
  const latest = history[history.length - 1];
  const oldest = history[0];
  const delta = latest.score - oldest.score;
  const color = colorForScore(latest.score);

  const DeltaIcon = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus;
  // Rising is worse (more red), falling is better (more green) -- the
  // opposite of a typical "up is good" metric, since this is a risk score.
  const deltaColor = delta > 0 ? "text-critical" : delta < 0 ? "text-low" : "text-muted";

  return (
    <>
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-2xl font-bold tabular-nums" style={{ color }}>
          {latest.score}
        </span>
        <span className={`flex items-center gap-1 text-xs font-medium ${deltaColor}`}>
          <DeltaIcon className="h-3.5 w-3.5" />
          {delta === 0 ? "flat" : `${delta > 0 ? "+" : ""}${delta}`} over {history.length} day{history.length === 1 ? "" : "s"}
        </span>
      </div>
      <ResponsiveContainer width="100%" height={100}>
        <AreaChart data={history} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
          <defs>
            <linearGradient id="threatScoreFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={color} stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="date" hide />
          <YAxis domain={[0, 100]} hide />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#232841" }} />
          <Area type="monotone" dataKey="score" stroke={color} strokeWidth={2} fill="url(#threatScoreFill)" dot={false} activeDot={{ r: 3.5, fill: color }} />
        </AreaChart>
      </ResponsiveContainer>
    </>
  );
}
