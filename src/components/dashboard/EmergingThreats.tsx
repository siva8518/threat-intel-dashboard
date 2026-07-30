import { ExternalLink, Flame, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { SeverityBadge } from "./SeverityBadge";
import { IndustryHeatmap, INDUSTRY_EMOJI } from "./IndustryHeatmap";
import { useEmergingThreatsRanking } from "@/hooks/useEmergingThreatsRanking";
import type { EmergingThreatEntry, IndustryRelevanceLevel } from "@/types/threat-intel";

const PRIORITY_VARIANT: Record<string, "critical" | "high" | "medium" | "low"> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
};

const RELEVANCE_VARIANT: Record<IndustryRelevanceLevel, "critical" | "high" | "medium" | "low" | "muted"> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  "Not Applicable": "muted",
};

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / (60 * 60 * 1000));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function scoreBreakdownTitle(entry: EmergingThreatEntry) {
  const f = entry.threatPriorityScore.factors;
  const line = (label: string, factor: { value: number; weight: number; contribution: number }) =>
    `${label}: ${Math.round(factor.value)} × ${Math.round(factor.weight * 100)}w = ${factor.contribution.toFixed(1)}`;
  return [
    "Threat Priority Score -- a transparent weighted heuristic, not an industry-standard metric.",
    line(entry.hasReport ? "AI risk score" : "Severity-tier risk (no AI report yet)", f.risk),
    line("Known exploited (KEV)", f.kev),
    line("Peak industry risk", f.industryRisk),
    line("Recency", f.recency),
  ].join("\n");
}

function ThreatRow({ entry }: { entry: EmergingThreatEntry }) {
  return (
    <a
      href={entry.id}
      target="_blank"
      rel="noreferrer"
      className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2.5 transition-colors hover:border-white/20"
    >
      <div
        className="flex h-11 w-11 shrink-0 flex-col items-center justify-center rounded-lg border border-primary/25 bg-primary/10 text-sm font-bold tabular-nums text-foreground"
        title={scoreBreakdownTitle(entry)}
      >
        {entry.threatPriorityScore.score}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="truncate text-sm font-semibold text-foreground">{entry.articleTitle}</span>
          <SeverityBadge severity={entry.severity} />
          {entry.aiRiskPriority && <Badge variant={PRIORITY_VARIANT[entry.aiRiskPriority] ?? "medium"}>{entry.aiRiskPriority}</Badge>}
          {entry.knownExploited && (
            <Badge variant="critical" className="gap-1">
              <ShieldAlert className="h-3 w-3" />
              KEV
            </Badge>
          )}
          {entry.topIndustry && (
            <Badge variant={RELEVANCE_VARIANT[entry.topIndustry.relevance]}>
              {INDUSTRY_EMOJI[entry.topIndustry.industry]} {entry.topIndustry.industry}
            </Badge>
          )}
          {entry.hasReport && (
            <Badge variant="cyan" title="A full AI Summarization report exists for this article -- see the AI Summarization tab">
              AI Report
            </Badge>
          )}
        </div>
        <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted">
          {entry.articleSource} &middot; {timeAgo(entry.publishedDate)}
        </div>
      </div>
      <ExternalLink className="h-3.5 w-3.5 shrink-0 text-muted" />
    </a>
  );
}

/**
 * Every recent article across the full ~200-source news pool (last 30 days),
 * ranked by a transparent, deterministically-computed Threat Priority Score
 * (risk tier + KEV status + peak per-industry risk + recency -- see
 * server/emergingThreatsRanking.js, and hover a score for the exact
 * breakdown, same pattern as the Overview tab's Critical Threat Level tile),
 * plus the aggregate industry heatmap rolled up across every AI Summarization
 * report's own per-sector assessment. Deliberately NOT limited to articles
 * with a full AI report -- that pipeline only covers a small daily slice of
 * the pool, so entries here are enriched with report data (a sharper risk
 * score, an industry badge, an "AI Report" tag) when one exists, but every
 * recent article is rankable regardless. Reached from the Overview tab's
 * "Emerging Threats Feed" widget.
 */
export function EmergingThreats() {
  const { data, isLoading, isError, error } = useEmergingThreatsRanking();

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <ShieldAlert className="h-4 w-4 text-primary" />
            Industry Heatmap
          </CardTitle>
          <p className="mt-1 text-xs text-muted">
            The worst relevance/risk seen for each sector across every AI Summarization report currently on file -- not just one article's view. Click a row for the
            full assessment.
          </p>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <Skeleton className="h-64 w-full" />
          ) : isError || !data ? (
            <ErrorState message={(error as Error)?.message ?? "Emerging Threats is unavailable right now."} />
          ) : (
            <IndustryHeatmap
              rows={data.industryHeatmap.map((row) => ({
                ...row,
                subtitle: row.activeThreatCount > 0 ? `(${row.activeThreatCount} active)` : undefined,
              }))}
            />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <Flame className="h-4 w-4 text-primary" />
            Ranked Threats <span className="font-normal text-muted">({data?.entries.length ?? 0})</span>
          </CardTitle>
          <p className="mt-1 text-xs text-muted">
            Every article across all sources from the last 30 days, ranked by Threat Priority Score -- hover a score for the factor breakdown. Entries tagged{" "}
            <span className="font-semibold text-accent-cyan">AI Report</span> have a full AI Summarization report backing a sharper score.
          </p>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          ) : isError || !data ? (
            <ErrorState message={(error as Error)?.message ?? "Emerging Threats is unavailable right now."} />
          ) : data.entries.length === 0 ? (
            <EmptyState message="No AI Summarization reports yet -- this list fills in as reports are generated." />
          ) : (
            <div className="space-y-2">
              {data.entries.map((entry) => (
                <ThreatRow key={entry.id} entry={entry} />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
