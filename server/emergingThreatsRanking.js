// Ranks the FULL tagged news pool (server/newsCorrelation.js#tagNewsItems --
// the same ~200-source pool Daily Summary/Security News/Watchlist already
// read from) by a transparent "Threat Priority Score", enriched with the
// richer per-article AI Summarization data (industryRelevance, aiRiskScoring)
// when a report happens to exist for that article -- but never gated on one.
// Powers the "Emerging Threats" tab and the Overview widget above it.
//
// Deliberately NOT scoped to AI Summarization reports alone: that pipeline
// only covers ~20 articles/day out of a ~200-source, thousands-strong pool
// (see server/aiThreatSummaryJob.js's own backlog comments), so a ranking
// that only considered reported articles would silently miss the vast
// majority of "emerging" activity, not just show it late. A report, when one
// exists, sharpens the score (a real aiRiskScoring.score instead of a
// severity-tier proxy, plus the per-industry risk factor) -- it's a bonus
// signal, not a requirement to appear at all.
//
// Named distinctly from server/connectors/emergingThreats.js (Proofpoint's
// unrelated compromised-IP blocklist connector, cache id "emerging-threats")
// to avoid any confusion between the two -- this module never touches that
// connector or its cache entry.
import { INDUSTRY_CATALOG } from "./aiThreatSummary.js";

const WEIGHTS = { risk: 0.4, kev: 0.15, industryRisk: 0.25, recency: 0.2 };
const RECENCY_FULL_WINDOW_MS = 24 * 60 * 60 * 1000; // full recency credit for anything published in the last 24h
const RECENCY_ZERO_WINDOW_MS = 7 * 24 * 60 * 60 * 1000; // linearly decays to zero credit by 7 days old
const POOL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // how far back the ranked pool reaches at all -- matches this app's existing "last 30 days" convention (see CveSeverityDistribution)
const MAX_ENTRIES = 150; // cap the response payload -- the pool itself can run past a thousand recent items across ~200 sources

// A tagged news item has no numeric risk score of its own (see
// server/newsCorrelation.js#computeSeverity, a 4-tier classification) --
// this maps that tier to roughly the same scale aiRiskScoring.score already
// uses, so a report-backed and non-report-backed article are comparable on
// the same axis rather than two incompatible scales.
const SEVERITY_BASE_SCORE = { critical: 100, high: 70, medium: 40, low: 15 };

function recencyScore(publishedDate) {
  const age = Date.now() - new Date(publishedDate).getTime();
  if (age <= RECENCY_FULL_WINDOW_MS) return 100;
  if (age >= RECENCY_ZERO_WINDOW_MS) return 0;
  const span = RECENCY_ZERO_WINDOW_MS - RECENCY_FULL_WINDOW_MS;
  return Math.round(100 * (1 - (age - RECENCY_FULL_WINDOW_MS) / span));
}

function maxIndustryRisk(report) {
  const rows = report?.industryRelevance ?? [];
  return rows.reduce((max, r) => Math.max(max, typeof r.riskScore === "number" ? r.riskScore : 0), 0);
}

// Real, cross-referenced KEV status for every article, not just reported
// ones -- a report's own grounded cves[] is used when present (already
// verified against NVD/KEV at generation time), otherwise this cross-
// references the article's own regex-extracted CVE mentions directly
// against the live KEV catalog, same "verify, don't guess" pattern used
// throughout this app rather than leaving non-reported articles with no KEV
// signal at all.
function isKevMatch(item, report, kevIds) {
  if (report?.cves?.length) return report.cves.some((c) => c.knownExploited);
  return (item.tags?.cveIds ?? []).some((id) => kevIds.has(id));
}

/** @returns {{score: number, factors: Record<string, {value: number, weight: number, contribution: number}>}} */
export function computeThreatPriorityScore(item, report, kevIds) {
  const risk = report?.aiRiskScoring?.score ?? SEVERITY_BASE_SCORE[item.severity] ?? SEVERITY_BASE_SCORE.low;
  const kev = isKevMatch(item, report, kevIds);
  const industryRisk = maxIndustryRisk(report) * 10; // 0-10 -> 0-100
  const recency = recencyScore(item.publishedDate);

  const factors = {
    risk: { value: risk, weight: WEIGHTS.risk, contribution: risk * WEIGHTS.risk },
    kev: { value: kev ? 100 : 0, weight: WEIGHTS.kev, contribution: (kev ? 100 : 0) * WEIGHTS.kev },
    industryRisk: { value: industryRisk, weight: WEIGHTS.industryRisk, contribution: industryRisk * WEIGHTS.industryRisk },
    recency: { value: recency, weight: WEIGHTS.recency, contribution: recency * WEIGHTS.recency },
  };
  const score = Math.round(Object.values(factors).reduce((sum, f) => sum + f.contribution, 0));
  return { score, factors };
}

function toRankedEntry(item, report, kevIds) {
  const topIndustry = report ? [...(report.industryRelevance ?? [])].sort((a, b) => b.riskScore - a.riskScore)[0] : null;
  return {
    id: item.link,
    articleTitle: item.title,
    articleSource: item.source,
    severity: report?.severity ?? item.severity.toUpperCase(),
    publishedDate: item.publishedDate,
    aiRiskPriority: report?.aiRiskScoring?.priority ?? null,
    knownExploited: isKevMatch(item, report, kevIds),
    hasReport: Boolean(report),
    topIndustry: topIndustry && topIndustry.relevance !== "Not Applicable" ? { industry: topIndustry.industry, relevance: topIndustry.relevance } : null,
    threatPriorityScore: computeThreatPriorityScore(item, report, kevIds),
  };
}

/**
 * @param {Array} taggedNewsItems - server/newsCorrelation.js#tagNewsItems output, the full ~200-source pool
 * @param {Array} reports - getAllReports() from server/aiThreatSummaryStore.js -- used to enrich matching articles (by link), never to filter the pool
 * @param {Set<string>} kevIds
 */
export function buildEmergingThreatsRanking(taggedNewsItems, reports, kevIds) {
  const reportsByLink = new Map(reports.map((r) => [r.id, r]));
  const now = Date.now();

  // The underlying news pool can legitimately contain the same link twice
  // (e.g. a source syncing the same advisory into more than one feed
  // category) -- deduped here by link, first occurrence wins, both because
  // ranking the same article twice is noise, not signal, and because `id`
  // (the link) is this list's React key, so duplicates would collide.
  const seen = new Set();

  return taggedNewsItems
    .filter((item) => now - new Date(item.publishedDate).getTime() <= POOL_WINDOW_MS)
    .filter((item) => {
      if (seen.has(item.link)) return false;
      seen.add(item.link);
      return true;
    })
    .map((item) => toRankedEntry(item, reportsByLink.get(item.link) ?? null, kevIds))
    .sort((a, b) => b.threatPriorityScore.score - a.threatPriorityScore.score || new Date(b.publishedDate) - new Date(a.publishedDate))
    .slice(0, MAX_ENTRIES);
}

const RELEVANCE_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, "Not Applicable": 0 };

/**
 * Rolls up every AI Summarization report's own per-industry assessment into
 * one heatmap: for each of the 10 sectors, the worst (highest-relevance,
 * tie-broken by highest-risk) hit seen across all reports, plus how many
 * reports currently flag it Critical/High. Industry-relevance detail is
 * AI-generated (there's no cheap keyword equivalent for the richer
 * why/impact/assets/defensive-focus fields), so unlike the ranked list above
 * this genuinely can only draw from reports -- it stays a smaller, slower-
 * growing picture than the ranked feed, by nature of what it's built from.
 */
export function computeAggregateIndustryHeatmap(reports) {
  const byIndustry = new Map(
    INDUSTRY_CATALOG.map((industry) => [industry, { industry, relevance: "Not Applicable", confidence: "Low", riskScore: 0, priority: "Low", whyAffected: "Not Applicable", potentialImpact: [], likelyTargetAssets: [], defensiveFocus: [], activeThreatCount: 0, topReport: null }]),
  );

  for (const report of reports) {
    for (const row of report.industryRelevance ?? []) {
      const agg = byIndustry.get(row.industry);
      if (!agg) continue;
      if (row.relevance === "Critical" || row.relevance === "High") agg.activeThreatCount += 1;
      const isWorse = RELEVANCE_RANK[row.relevance] > RELEVANCE_RANK[agg.relevance] || (RELEVANCE_RANK[row.relevance] === RELEVANCE_RANK[agg.relevance] && row.riskScore > agg.riskScore);
      if (isWorse) {
        agg.relevance = row.relevance;
        agg.confidence = row.confidence;
        agg.riskScore = row.riskScore;
        agg.priority = row.priority;
        agg.whyAffected = row.whyAffected;
        agg.potentialImpact = row.potentialImpact;
        agg.likelyTargetAssets = row.likelyTargetAssets;
        agg.defensiveFocus = row.defensiveFocus;
        agg.topReport = { id: report.id, title: report.articleTitle };
      }
    }
  }

  return [...byIndustry.values()];
}
