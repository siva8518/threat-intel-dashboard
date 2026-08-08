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
import { taggingIndustries } from "./industryClassification.js";

const WEIGHTS = { risk: 0.35, kev: 0.15, namedThreat: 0.15, industryRisk: 0.2, recency: 0.15 };
const RECENCY_FULL_WINDOW_MS = 24 * 60 * 60 * 1000; // full recency credit for anything published in the last 24h
const RECENCY_ZERO_WINDOW_MS = 7 * 24 * 60 * 60 * 1000; // linearly decays to zero credit by 7 days old
const POOL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000; // how far back the ranked pool reaches at all -- matches this app's existing "last 30 days" convention (see CveSeverityDistribution)
const MAX_ENTRIES = 150; // cap the response payload -- the pool itself can run past a thousand recent items across ~200 sources
const MAX_CONTRIBUTING_ARTICLES = 20; // cap per-industry article list shown in the heatmap's expanded detail -- activeThreatCount stays the true total even once a sector's list is capped

// A tagged news item has no numeric risk score of its own (see
// server/newsCorrelation.js#computeSeverity, a 4-tier classification) --
// this maps that tier to roughly the same scale aiRiskScoring.score already
// uses, so a report-backed and non-report-backed article are comparable on
// the same axis rather than two incompatible scales.
const SEVERITY_BASE_SCORE = { critical: 100, high: 70, medium: 40, low: 15 };

// computeSeverity() in server/newsCorrelation.js can only reach "critical"
// via a CVE tied to KEV/high-EPSS -- a named ransomware group or threat
// actor campaign with no CVE mention structurally tops out at "medium"/
// "high" there, which would silently shut every malware/actor-driven
// article out of the top of this ranking even when it's just as urgent as
// a KEV vulnerability. This floor (not an override -- Math.max keeps
// whatever's higher) gives named actor/malware activity a score competitive
// with CVE/KEV content instead of being structurally capped below it.
function actorMalwareFloor(item) {
  const hasActor = (item.tags?.actors?.length ?? 0) > 0;
  const hasMalware = (item.tags?.malware?.length ?? 0) > 0;
  if (hasActor && hasMalware) return 85; // a named campaign attributed to both an actor and a malware family -- strong signal
  if (hasActor || hasMalware) return 65;
  return 0;
}

// Mirrors isKevMatch()'s role for CVE content: a dedicated bonus channel for
// named actor/malware activity, not just a floor on the risk sub-score.
// Confirmed live that the floor alone still left a structural gap -- a
// KEV-tied CVE gets both a maxed-out risk value (100, since computeSeverity
// reaches "critical" via KEV/high-EPSS) AND the flat +15-weighted kev bonus
// on top, while an actor+malware article only ever touched the risk
// sub-score (capped at 85 there), so it could never actually catch up even
// with the floor in place (a KEV CVE scored ~75 vs. ~54 for the best-case
// named campaign, same recency). This factor gives named-campaign articles
// the same second bonus channel KEV articles already had.
function namedThreatBonus(item) {
  const hasActor = (item.tags?.actors?.length ?? 0) > 0;
  const hasMalware = (item.tags?.malware?.length ?? 0) > 0;
  if (hasActor && hasMalware) return 100;
  if (hasActor || hasMalware) return 50;
  return 0;
}

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
  const baseRisk = report?.aiRiskScoring?.score ?? SEVERITY_BASE_SCORE[item.severity] ?? SEVERITY_BASE_SCORE.low;
  const risk = Math.max(baseRisk, actorMalwareFloor(item));
  const kev = isKevMatch(item, report, kevIds);
  const namedThreat = namedThreatBonus(item);
  const industryRisk = maxIndustryRisk(report) * 10; // 0-10 -> 0-100
  const recency = recencyScore(item.publishedDate);

  const factors = {
    risk: { value: risk, weight: WEIGHTS.risk, contribution: risk * WEIGHTS.risk },
    kev: { value: kev ? 100 : 0, weight: WEIGHTS.kev, contribution: (kev ? 100 : 0) * WEIGHTS.kev },
    namedThreat: { value: namedThreat, weight: WEIGHTS.namedThreat, contribution: namedThreat * WEIGHTS.namedThreat },
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

const DIVERSITY_HEAD_SIZE = 12; // how many leading slots get category-guaranteed, before falling back to pure score order -- comfortably covers the Overview widget's own top-10 slice of this same list
const DIVERSITY_CATEGORIES = ["ransomware", "threatActor", "malware", "cve"];

// A single best-fit label per article, used only to decide diversity-head
// placement below -- never affects the score itself. Precedence favors the
// more specific/newsworthy signal when an article matches more than one
// (e.g. "CVE-2026-0257 Leads to Qilin Ransomware" is labeled "ransomware",
// not "cve", since that's the more useful bucket to guarantee visibility
// for). ransomwareGroupNames distinguishes a ransomware-attributed actor
// hit from a generic threat-actor hit (e.g. an APT/nation-state group) --
// tags.actors alone can't tell them apart, since ransomware group names are
// folded into the same actor set (see getTaggedNewsItems in
// server/newsCorrelation.js).
function categorizeForDiversity(item, ransomwareGroupNames) {
  const actors = item.tags?.actors ?? [];
  const malware = item.tags?.malware ?? [];
  const cveIds = item.tags?.cveIds ?? [];
  if (actors.some((a) => ransomwareGroupNames.has(a.toLowerCase()))) return "ransomware";
  if (actors.length > 0) return "threatActor";
  if (malware.length > 0) return "malware";
  if (cveIds.length > 0) return "cve";
  return "general";
}

// Confirmed live that closing the scoring gap (see namedThreat above) still
// wasn't enough on its own -- pure score order means whichever category has
// the deepest bench of high-scoring articles on a given day (usually CVE/KEV
// advisories, since there are structurally more of those than ransomware/
// actor hits) can still fill the entire visible head, even when real
// ransomware/malware/actor activity exists further down the list. This
// round-robins the best not-yet-picked article from each of
// ransomware/threatActor/malware/cve into the first DIVERSITY_HEAD_SIZE
// slots (skipping any category with nothing left, never fabricating or
// padding), so the head -- what a user actually sees without scrolling --
// always reflects the real mix of activity instead of one format
// dominating by score alone. Score-desc order is preserved for everything
// after the head; "general" articles (no cve/actor/malware tag at all)
// don't compete for head slots since the goal is guaranteeing those four
// specific categories, not diluting them with untagged news.
function diversifyHead(pairs, ransomwareGroupNames) {
  const byCategory = { ransomware: [], threatActor: [], malware: [], cve: [] };
  for (const p of pairs) {
    const category = categorizeForDiversity(p.item, ransomwareGroupNames);
    if (byCategory[category]) byCategory[category].push(p);
  }

  const picked = new Set();
  const head = [];
  const cursor = { ransomware: 0, threatActor: 0, malware: 0, cve: 0 };
  while (head.length < DIVERSITY_HEAD_SIZE) {
    let progressed = false;
    for (const category of DIVERSITY_CATEGORIES) {
      if (head.length >= DIVERSITY_HEAD_SIZE) break;
      const bucket = byCategory[category];
      while (cursor[category] < bucket.length && picked.has(bucket[cursor[category]].item.link)) cursor[category]++;
      if (cursor[category] < bucket.length) {
        const p = bucket[cursor[category]];
        head.push(p);
        picked.add(p.item.link);
        cursor[category]++;
        progressed = true;
      }
    }
    if (!progressed) break; // every category exhausted -- nothing left to guarantee
  }

  const rest = pairs.filter((p) => !picked.has(p.item.link));
  return [...head, ...rest];
}

/**
 * @param {Array} taggedNewsItems - server/newsCorrelation.js#tagNewsItems output, the full ~200-source pool
 * @param {Array} reports - getAllReports() from server/aiThreatSummaryStore.js -- used to enrich matching articles (by link), never to filter the pool
 * @param {Set<string>} kevIds
 * @param {Set<string>} ransomwareGroupNames - lowercased ransomware group names (see server/ransomwareCampaigns.js), used only to tell a ransomware-attributed article apart from a generic threat-actor one for diversifyHead() above
 */
export function buildEmergingThreatsRanking(taggedNewsItems, reports, kevIds, ransomwareGroupNames = new Set()) {
  const reportsByLink = new Map(reports.map((r) => [r.id, r]));
  const now = Date.now();

  // The underlying news pool can legitimately contain the same link twice
  // (e.g. a source syncing the same advisory into more than one feed
  // category) -- deduped here by link, first occurrence wins, both because
  // ranking the same article twice is noise, not signal, and because `id`
  // (the link) is this list's React key, so duplicates would collide.
  const seen = new Set();

  const pairs = taggedNewsItems
    .filter((item) => now - new Date(item.publishedDate).getTime() <= POOL_WINDOW_MS)
    .filter((item) => {
      if (seen.has(item.link)) return false;
      seen.add(item.link);
      return true;
    })
    .map((item) => ({ item, entry: toRankedEntry(item, reportsByLink.get(item.link) ?? null, kevIds) }))
    .sort((a, b) => b.entry.threatPriorityScore.score - a.entry.threatPriorityScore.score || new Date(b.entry.publishedDate) - new Date(a.entry.publishedDate));

  return diversifyHead(pairs, ransomwareGroupNames)
    .slice(0, MAX_ENTRIES)
    .map((p) => p.entry);
}

const RELEVANCE_RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, "Not Applicable": 0 };
const SEVERITY_TO_RELEVANCE = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const RELEVANCE_TO_PRIORITY = { Critical: "Immediate", High: "High", Medium: "Normal", Low: "Low" };

/**
 * Industry relevance for one article -- re-exports server/industryClassification.js's
 * unified engine (explicit-targeting text match UNION technology/vendor
 * relevance against the full title+summary, not title-only) so this file's
 * many internal callers (computeAggregateIndustryHeatmap, the ranked feed
 * below) and server/industryBriefing.js (which reuses this same export)
 * don't each need their own import. Formerly a second, independent 14-sector
 * implementation duplicating server/newsCorrelation.js's own (differently
 * scoped, differently tiered) matchIndustries() -- both now delegate to the
 * one engine.
 */
export function matchIndustries(title, summary) {
  return taggingIndustries(summary ? `${title} ${summary}` : title);
}

/**
 * For each of the 10 sectors, the worst (highest-relevance, tie-broken by
 * highest-risk) hit seen across the full recent news pool -- keyword-matched
 * against each article's title and scored from its own tagged severity, the
 * same cheap signal already used for "Industries Targeted" on Overview
 * (server/newsCorrelation.js#matchIndustries), not gated on AI Summarization
 * coverage. When a report DOES exist for a matching article and rates that
 * sector at least as relevant, its richer why/impact/assets/defensive-focus
 * assessment is used instead of the keyword-derived stand-in -- enrichment,
 * same "bonus signal, never a requirement" pattern as the ranked feed above.
 */
export function computeAggregateIndustryHeatmap(taggedNewsItems, reports) {
  const byIndustry = new Map(
    INDUSTRY_CATALOG.map((industry) => [
      industry,
      { industry, relevance: "Not Applicable", confidence: "Low", riskScore: 0, priority: "Low", whyAffected: "Not Applicable", potentialImpact: [], likelyTargetAssets: [], defensiveFocus: [], activeThreatCount: 0, topArticle: null, contributingArticles: [] },
    ]),
  );
  const reportsByLink = new Map(reports.map((r) => [r.id, r]));
  const now = Date.now();

  for (const item of taggedNewsItems) {
    if (now - new Date(item.publishedDate).getTime() > POOL_WINDOW_MS) continue;
    const matchedIndustries = matchIndustries(item.title);
    if (matchedIndustries.length === 0) continue;

    const keywordRelevance = SEVERITY_TO_RELEVANCE[item.severity] ?? "Low";
    const keywordRiskScore = Math.round((SEVERITY_BASE_SCORE[item.severity] ?? SEVERITY_BASE_SCORE.low) / 10);
    const report = reportsByLink.get(item.link);

    for (const industry of matchedIndustries) {
      const agg = byIndustry.get(industry);
      if (!agg) continue;

      const reportRow = report?.industryRelevance?.find((r) => r.industry === industry);
      const useReportRow = reportRow && RELEVANCE_RANK[reportRow.relevance] >= RELEVANCE_RANK[keywordRelevance];
      const candidateRelevance = useReportRow ? reportRow.relevance : keywordRelevance;
      const candidateRiskScore = useReportRow ? reportRow.riskScore : keywordRiskScore;

      if (candidateRelevance === "Critical" || candidateRelevance === "High") {
        agg.activeThreatCount += 1;
        agg.contributingArticles.push({ id: item.link, title: item.title, source: item.source, relevance: candidateRelevance, publishedDate: item.publishedDate });
      }

      const isWorse = RELEVANCE_RANK[candidateRelevance] > RELEVANCE_RANK[agg.relevance] || (RELEVANCE_RANK[candidateRelevance] === RELEVANCE_RANK[agg.relevance] && candidateRiskScore > agg.riskScore);
      if (!isWorse) continue;

      if (useReportRow) {
        agg.relevance = reportRow.relevance;
        agg.confidence = reportRow.confidence;
        agg.riskScore = reportRow.riskScore;
        agg.priority = reportRow.priority;
        agg.whyAffected = reportRow.whyAffected;
        agg.potentialImpact = reportRow.potentialImpact;
        agg.likelyTargetAssets = reportRow.likelyTargetAssets;
        agg.defensiveFocus = reportRow.defensiveFocus;
      } else {
        agg.relevance = keywordRelevance;
        agg.confidence = "Low"; // keyword-derived, not an AI assessment
        agg.riskScore = keywordRiskScore;
        agg.priority = RELEVANCE_TO_PRIORITY[keywordRelevance];
        agg.whyAffected = `Derived from recent news coverage matching this sector's keywords (not yet AI-assessed) -- e.g. "${item.title}"`;
        agg.potentialImpact = [];
        agg.likelyTargetAssets = [];
        agg.defensiveFocus = [];
      }
      agg.topArticle = { id: item.link, title: item.title };
    }
  }

  return [...byIndustry.values()].map((agg) => ({
    ...agg,
    contributingArticles: agg.contributingArticles
      .sort((a, b) => RELEVANCE_RANK[b.relevance] - RELEVANCE_RANK[a.relevance] || new Date(b.publishedDate) - new Date(a.publishedDate))
      .slice(0, MAX_CONTRIBUTING_ARTICLES),
  }));
}
