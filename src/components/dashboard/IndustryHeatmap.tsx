import { Fragment, useState } from "react";
import { ExternalLink, Loader2, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { AiThreatSummaryIndustryRelevance, IndustryName, IndustryRelevanceLevel } from "@/types/threat-intel";

export const INDUSTRY_EMOJI: Record<IndustryName, string> = {
  "Financial Services": "🏦",
  Healthcare: "🏥",
  Government: "🏛",
  Manufacturing: "🏭",
  Retail: "🛒",
  Technology: "💻",
  Telecommunications: "📡",
  "Energy & Utilities": "⚡",
  Education: "🎓",
  "Transportation & Logistics": "🚚",
  "Media & Entertainment": "🎬",
  Hospitality: "🏨",
  Insurance: "📄",
  Pharmaceuticals: "💊",
  "Professional Services": "💼",
  "Defense & Aerospace": "🛡",
  Automotive: "🚗",
  "Real Estate": "🏢",
  Construction: "🏗",
  Agriculture: "🌾",
  "Cross-Industry / Enterprise": "🏢",
};

const RELEVANCE_BADGE_VARIANT: Record<IndustryRelevanceLevel, "critical" | "high" | "medium" | "low" | "muted"> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  "Not Applicable": "muted",
};

const RELEVANCE_DOT: Record<IndustryRelevanceLevel, string> = {
  Critical: "🔴",
  High: "🟠",
  Medium: "🟡",
  Low: "🟢",
  "Not Applicable": "⚪",
};

export const RELEVANCE_RANK: Record<IndustryRelevanceLevel, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, "Not Applicable": 0 };

export interface IndustryHeatmapRow extends AiThreatSummaryIndustryRelevance {
  /** Extra context shown next to the industry name in aggregate views (e.g. "3 active reports"). */
  subtitle?: string;
  /** Aggregate views only -- the Critical/High articles backing activeThreatCount, so a user can verify the claim instead of just trusting a number. */
  contributingArticles?: { id: string; title: string; source: string; relevance: IndustryRelevanceLevel; publishedDate: string }[];
}

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / (60 * 60 * 1000));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

/**
 * Shared industry-relevance heatmap table -- used both per-report (AI
 * Summarization's own 10-sector assessment, see server/aiThreatSummary.js's
 * INDUSTRY_CATALOG) and aggregated across all reports (the Emerging Threats
 * tab). Rows sort by relevance severity so genuinely elevated sectors surface
 * first -- most rows are "Not Applicable"/"Low" by design (see the grounding
 * rule in the prompt: only 1-3 sectors should ever be Critical/High for a
 * typical article), so this is deliberately compact by default with detail
 * behind a click, not ten walls of text.
 */
export function IndustryHeatmap({
  rows,
  onGenerateBriefing,
  pendingIndustry,
}: {
  rows: IndustryHeatmapRow[];
  onGenerateBriefing?: (industry: IndustryName) => void;
  /** Which industry's briefing mutation is currently in flight, if any -- swaps that row's button to a disabled spinner so a click has immediate, visible feedback instead of appearing to do nothing while the (multi-second, LLM-backed) request resolves. */
  pendingIndustry?: IndustryName | null;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const sorted = [...rows].sort((a, b) => RELEVANCE_RANK[b.relevance] - RELEVANCE_RANK[a.relevance] || b.riskScore - a.riskScore);

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[560px] border-collapse text-sm">
        <thead>
          <tr className="border-b border-white/10 text-left text-xs uppercase tracking-wider text-muted">
            <th className="py-1.5 pr-3 font-semibold">Industry</th>
            <th className="py-1.5 pr-3 font-semibold">Relevance</th>
            <th className="py-1.5 pr-3 font-semibold">Risk</th>
            <th className="py-1.5 font-semibold">Priority</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const isOpen = expanded === row.industry;
            const applicable = row.relevance !== "Not Applicable";
            // "Not Applicable" here only means the last 30 days of news found
            // no elevated signal -- the on-demand briefing searches a wider
            // 90-day window and can still find enough to generate from (e.g.
            // Energy & Utilities: Not Applicable here, but a real briefing
            // exists), so the row must stay reachable whenever that action
            // is available, even with nothing else to show in this table.
            const canExpand = applicable || Boolean(onGenerateBriefing);
            return (
              <Fragment key={row.industry}>
                <tr
                  onClick={() => canExpand && setExpanded(isOpen ? null : row.industry)}
                  className={cn("border-b border-white/[0.05]", canExpand && "cursor-pointer hover:bg-white/[0.02]")}
                >
                  <td className="py-2 pr-3 text-foreground">
                    <span className="mr-1.5" aria-hidden="true">
                      {INDUSTRY_EMOJI[row.industry]}
                    </span>
                    {row.industry}
                    {row.subtitle && <span className="ml-1.5 text-xs text-muted">{row.subtitle}</span>}
                  </td>
                  <td className="py-2 pr-3">
                    <Badge variant={RELEVANCE_BADGE_VARIANT[row.relevance]}>
                      <span aria-hidden="true">{RELEVANCE_DOT[row.relevance]}</span> {row.relevance}
                    </Badge>
                  </td>
                  <td className="py-2 pr-3 tabular-nums text-foreground">{row.riskScore}/10</td>
                  <td className="py-2 text-muted">{row.priority}</td>
                </tr>
                {isOpen && canExpand && (
                  <tr className="border-b border-white/[0.05] bg-white/[0.02]">
                    <td colSpan={4} className="px-2 py-3 text-xs">
                      {applicable ? (
                        <>
                          <p className="mb-2 text-foreground">
                            <span className="font-semibold">Why: </span>
                            {row.whyAffected} <span className="text-muted">(confidence: {row.confidence})</span>
                          </p>
                          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                            {row.potentialImpact.length > 0 && (
                              <div>
                                <p className="mb-1 font-semibold text-foreground">Potential Impact</p>
                                <ul className="list-disc space-y-0.5 pl-4 text-muted">
                                  {row.potentialImpact.map((x, i) => (
                                    <li key={i}>{x}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {row.likelyTargetAssets.length > 0 && (
                              <div>
                                <p className="mb-1 font-semibold text-foreground">Likely Target Assets</p>
                                <ul className="list-disc space-y-0.5 pl-4 text-muted">
                                  {row.likelyTargetAssets.map((x, i) => (
                                    <li key={i}>{x}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {row.defensiveFocus.length > 0 && (
                              <div>
                                <p className="mb-1 font-semibold text-foreground">Defensive Focus</p>
                                <ul className="list-disc space-y-0.5 pl-4 text-muted">
                                  {row.defensiveFocus.map((x, i) => (
                                    <li key={i}>{x}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                          {row.contributingArticles && row.contributingArticles.length > 0 && (
                            <div className="mt-3 border-t border-white/[0.05] pt-2.5">
                              <p className="mb-1.5 font-semibold text-foreground">
                                Source articles behind this sector's rating
                                {row.subtitle && <span className="ml-1 font-normal text-muted">{row.subtitle}</span>}
                              </p>
                              <ul className="space-y-1">
                                {row.contributingArticles.map((a) => (
                                  <li key={a.id}>
                                    <a
                                      href={a.id}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="flex items-center gap-1.5 text-muted transition-colors hover:text-foreground"
                                      onClick={(e) => e.stopPropagation()}
                                    >
                                      <Badge variant={RELEVANCE_BADGE_VARIANT[a.relevance]} className="shrink-0">
                                        {a.relevance}
                                      </Badge>
                                      <span className="truncate">{a.title}</span>
                                      <span className="shrink-0 text-[11px]">
                                        ({a.source} &middot; {timeAgo(a.publishedDate)})
                                      </span>
                                      <ExternalLink className="h-3 w-3 shrink-0" />
                                    </a>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </>
                      ) : (
                        <p className="text-muted">
                          No elevated signal for this sector in the last 30 days of news. The full briefing searches a wider 90-day window and may still find enough
                          to generate from.
                        </p>
                      )}
                      {onGenerateBriefing && (
                        <button
                          type="button"
                          disabled={pendingIndustry === row.industry}
                          onClick={(e) => {
                            e.stopPropagation();
                            onGenerateBriefing(row.industry);
                          }}
                          className="mt-3 flex items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary transition-colors hover:bg-primary/20 disabled:cursor-wait disabled:opacity-70"
                        >
                          {pendingIndustry === row.industry ? (
                            <>
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              Generating…
                            </>
                          ) : (
                            <>
                              <Sparkles className="h-3.5 w-3.5" />
                              Generate Full Briefing
                            </>
                          )}
                        </button>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
