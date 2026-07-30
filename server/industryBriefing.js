// On-demand, per-industry deep-dive threat briefing -- reached by clicking
// "Generate Full Briefing" on an Industry Heatmap row (see
// server/emergingThreatsRanking.js, which computes that same heatmap and
// whose matchIndustries10()/INDUSTRY_CATALOG this module reuses rather than
// duplicating). Generated live per request, not scheduled/cached, since most
// of the 10 sectors won't be viewed in a given session -- see the "on-demand
// per industry" placement decision.
//
// Unlike server/aiThreatSummary.js (one article -> one deep-dive report),
// this synthesizes across MANY articles at once, so the model is given a
// compact table of real articles (title/source/date/severity/CVE/KEV/actor/
// malware) rather than full article text, and is required to cite which of
// those specific articles support each claim via sourceArticleIds. Every ID
// is validated against the real pool after parsing -- an invented ID is
// silently dropped, same "verify, don't guess" pattern as mitreAttack's
// techniqueId validation in aiThreatSummary.js. firstObserved and
// activeExploitation for each top-level threat are never trusted to the
// model at all -- both are recomputed programmatically from the validated
// source articles' own real dates/KEV status.
//
// The requesting spec asked for named-vendor references (CISA, Microsoft,
// Mandiant, etc.). To avoid inventing report titles/dates that don't exist,
// `references` is never model-authored -- it's built directly from the real
// grounding pool's own {title, source, link, publishedDate}, so "citing
// CISA" only happens when the underlying article really is from a CISA feed.
import { groqJson, GroqUnavailableError } from "./groqClient.js";
import { INDUSTRY_CATALOG } from "./aiThreatSummary.js";
import { matchIndustries10 } from "./emergingThreatsRanking.js";

const GROQ_CHAT_MODEL = process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile";

// Wider than the 30-day pool the rest of Emerging Threats uses -- this
// feature's own spec explicitly asks for a 60-90 day outlook grounded in
// "recent activity from the last 90 days where possible."
const POOL_WINDOW_MS = 90 * 24 * 60 * 60 * 1000;
const RECENT_HALF_MS = POOL_WINDOW_MS / 2;
const MAX_GROUNDING_ARTICLES = 50; // keeps the prompt a manageable size
const MAX_REFERENCES = 25;
const SEVERITY_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

export class InsufficientCoverageError extends Error {
  constructor(industry) {
    super(`Not enough recent source coverage for ${industry} to generate a grounded briefing.`);
    this.name = "InsufficientCoverageError";
  }
}

/**
 * The real, verifiable article pool a briefing for `industry` may draw from
 * -- keyword-matched (same signal as the aggregate heatmap) OR named
 * Critical/High by an existing AI Summarization report for this sector,
 * within the last 90 days. Capped and sorted by severity then recency so
 * the highest-signal articles survive the cap, not just the newest.
 */
export function poolForIndustry(industry, taggedNewsItems, reports, kevIds) {
  const reportsByLink = new Map(reports.map((r) => [r.id, r]));
  const now = Date.now();
  const matched = [];

  for (const item of taggedNewsItems) {
    const age = now - new Date(item.publishedDate).getTime();
    if (age > POOL_WINDOW_MS) continue;

    const report = reportsByLink.get(item.link);
    const reportRow = report?.industryRelevance?.find((r) => r.industry === industry);
    const keywordHit = matchIndustries10(item.title).includes(industry);
    const reportHit = reportRow && (reportRow.relevance === "Critical" || reportRow.relevance === "High");
    if (!keywordHit && !reportHit) continue;

    const cveIds = item.tags?.cveIds ?? [];
    matched.push({
      id: item.link,
      title: item.title,
      source: item.source,
      publishedDate: item.publishedDate,
      severity: report?.severity?.toLowerCase() ?? item.severity,
      cveIds,
      knownExploited: cveIds.some((id) => kevIds.has(id)) || Boolean(report?.cves?.some((c) => c.knownExploited)),
      actors: item.tags?.actors ?? [],
      malware: item.tags?.malware ?? [],
      reportRelevance: reportRow?.relevance ?? null,
    });
  }

  return matched
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || new Date(b.publishedDate) - new Date(a.publishedDate))
    .slice(0, MAX_GROUNDING_ARTICLES);
}

function buildGroundingTable(pool) {
  return pool
    .map((a, i) => {
      const bits = [`#${i + 1}`, `"${a.title}"`, a.source, new Date(a.publishedDate).toISOString().slice(0, 10), a.severity.toUpperCase()];
      if (a.cveIds.length) bits.push(a.cveIds.join(", "));
      if (a.knownExploited) bits.push("KNOWN EXPLOITED (KEV)");
      if (a.actors.length) bits.push(`actor: ${a.actors.join(", ")}`);
      if (a.malware.length) bits.push(`malware: ${a.malware.join(", ")}`);
      return bits.join(" | ");
    })
    .join("\n");
}

const SYSTEM_PROMPT =
  "You are a Senior Cyber Threat Intelligence Analyst producing a sector-specific briefing for CISOs, Threat Intelligence Analysts, and SOC teams. " +
  "You will be given a numbered table of real, verified recent articles (title, source, date, severity, CVE/KEV status, named actors/malware) that were matched to one specific industry. " +
  "This is a STRICT GROUNDING task: every claim you make must trace back to one or more numbered articles in that table, or to a clearly-hedged, well-established general pattern for a vulnerability/technique/actor CATEGORY (e.g. \"ransomware groups have historically moved quickly to double-extortion tactics\") -- never assert a specific unconfirmed fact about an incident, actor, or campaign that is not in the table. Never invent a CVE ID, a vendor report title, a statistic, or a date. If the table is thin for a section, write a short, honest section rather than padding it with generic filler or invented specifics. " +
  "Every entry that names a specific threat, actor, or technique MUST include \"sourceArticleIds\": an array of the article numbers (integers, e.g. [3, 7]) from the table that support it -- this is checked against the real table after you respond, and any number not in the table is discarded, so only cite numbers you actually see. Do not cite article numbers for an entry that isn't really grounded in them. " +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"executiveSummary": string, 3-5 short paragraphs separated by \\n\\n, a concise overview of the current threat landscape for this industry grounded in the table.\n' +
  '"topEmergingThreats": array of 5-10 {"name": string, "whyEmerging": string, "activityLevel": "Critical"|"High"|"Medium", "sourceArticleIds": int[]} -- distinct named threats/vulnerabilities/campaigns, each genuinely supported by the table, ranked most significant first. Do not include "firstObserved"/"activeExploitation"/"trend" -- those are computed separately from your citations.\n' +
  '"activeThreatActors": array of {"actor": string (must be an actor name that literally appears in the table\'s actor list), "motivation": string, "typicalTargets": string, "recentCampaigns": string, "ttps": string, "sourceArticleIds": int[]} -- [] if the table names no actors for this industry, do not invent one.\n' +
  '"emergingAttackTechniques": array of {"technique": string (e.g. "AI-assisted phishing", "ClickFix", "Cloud identity attacks", "Supply chain attacks" -- only ones genuinely evidenced by the table or a well-known category-level pattern relevant to this industry), "whyIncreasing": string, "sourceArticleIds": int[]}.\n' +
  '"commonTargets": string[] (4-8 specific assets/technologies this industry\'s attackers are shown targeting in the table, e.g. "Microsoft 365", "OT/ICS Systems", "Payment Systems" -- ground in the table, not a generic checklist).\n' +
  '"vulnerabilityTrendsCommentary": string, 2-3 sentences of narrative synthesis over the table\'s own CVE/KEV entries (which are listed separately and verified programmatically -- do not restate the raw CVE IDs here, comment on the pattern: frequently-affected vendors/products, internet-facing exposure, exploit maturity).\n' +
  '"industryRiskAssessment": {"currentThreatLevel": "Critical"|"High"|"Medium"|"Low", "mostLikelyAttackScenarios": string[] (2-4), "highestBusinessRisks": string[] (2-4), "technologiesRequiringAttention": string[] (2-5)}.\n' +
  '"recommendedDefensivePriorities": string[] of up to 10 items, ranked most urgent first, specific to this industry and this table -- not generic best-practices.\n' +
  '"threatIntelOutlook": string, 1-2 paragraphs on likely developments over the next 60-90 days, grounded only in the table\'s own trajectory or a clearly-hedged general pattern for the category -- never a specific unconfirmed prediction about a named incident.\n' +
  "No other text, no markdown formatting, no code fences.";

function safeString(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function safeStringArray(value, max = 10) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()).slice(0, max) : [];
}

const RELEVANCE_LEVELS = new Set(["Critical", "High", "Medium", "Low"]);

/** Validates sourceArticleIds against the real 1-indexed grounding table -- drops any number the model invented, returns the real pool entries (not just indices) so callers never re-look-up. */
function groundedArticles(sourceArticleIds, pool) {
  if (!Array.isArray(sourceArticleIds)) return [];
  const seen = new Set();
  const out = [];
  for (const n of sourceArticleIds) {
    const idx = Number(n) - 1;
    if (!Number.isInteger(idx) || idx < 0 || idx >= pool.length) continue;
    if (seen.has(idx)) continue;
    seen.add(idx);
    out.push(pool[idx]);
  }
  return out;
}

function computeTrend(articles) {
  if (articles.length < 2) return "Stable";
  const now = Date.now();
  const recent = articles.filter((a) => now - new Date(a.publishedDate).getTime() <= RECENT_HALF_MS).length;
  const older = articles.length - recent;
  if (older === 0) return "Increasing";
  if (recent / older >= 1.5) return "Increasing";
  if (recent / older <= 0.67) return "Declining";
  return "Stable";
}

function toArticleRef(a) {
  return { id: a.id, title: a.title, source: a.source, publishedDate: a.publishedDate };
}

function safeTopEmergingThreats(value, pool) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 10).map((t) => {
    const sources = groundedArticles(t?.sourceArticleIds, pool);
    return {
      name: safeString(t?.name, "Unnamed threat"),
      whyEmerging: safeString(t?.whyEmerging),
      activityLevel: RELEVANCE_LEVELS.has(t?.activityLevel) && t.activityLevel !== "Low" ? t.activityLevel : "Medium",
      firstObserved: sources.length ? sources.reduce((min, a) => (a.publishedDate < min ? a.publishedDate : min), sources[0].publishedDate) : null,
      activeExploitation: sources.some((a) => a.knownExploited),
      trend: computeTrend(sources),
      sourceArticles: sources.map(toArticleRef),
    };
  });
}

function safeActiveThreatActors(value, pool) {
  if (!Array.isArray(value)) return [];
  const knownActors = new Set(pool.flatMap((a) => a.actors.map((n) => n.toLowerCase())));
  return value
    .filter((t) => typeof t?.actor === "string" && knownActors.has(t.actor.toLowerCase()))
    .slice(0, 10)
    .map((t) => ({
      actor: t.actor.trim(),
      motivation: safeString(t.motivation, "Not stated in available reporting"),
      typicalTargets: safeString(t.typicalTargets, "Not stated in available reporting"),
      recentCampaigns: safeString(t.recentCampaigns, "Not stated in available reporting"),
      ttps: safeString(t.ttps, "Not stated in available reporting"),
      sourceArticles: groundedArticles(t.sourceArticleIds, pool).map(toArticleRef),
    }));
}

function safeAttackTechniques(value, pool) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 10).map((t) => ({
    technique: safeString(t?.technique, "Unnamed technique"),
    whyIncreasing: safeString(t?.whyIncreasing),
    sourceArticles: groundedArticles(t?.sourceArticleIds, pool).map(toArticleRef),
  }));
}

function safeRiskAssessment(value) {
  const v = value && typeof value === "object" ? value : {};
  return {
    currentThreatLevel: RELEVANCE_LEVELS.has(v.currentThreatLevel) ? v.currentThreatLevel : "Medium",
    mostLikelyAttackScenarios: safeStringArray(v.mostLikelyAttackScenarios, 4),
    highestBusinessRisks: safeStringArray(v.highestBusinessRisks, 4),
    technologiesRequiringAttention: safeStringArray(v.technologiesRequiringAttention, 5),
  };
}

/** Real, verified CVE/KEV entries pulled straight from the grounding pool -- never model-authored, so this can't invent a CVE ID or a KEV status. */
function vulnerabilityTrendsFromPool(pool) {
  const kevEntries = [];
  const seenCves = new Set();
  for (const a of pool) {
    for (const cveId of a.cveIds) {
      if (seenCves.has(cveId)) continue;
      seenCves.add(cveId);
      if (a.knownExploited) kevEntries.push({ cveId, articleTitle: a.title, articleId: a.id });
    }
  }
  return { kevEntries: kevEntries.slice(0, 20), totalUniqueCves: seenCves.size };
}

/**
 * @param {string} industry - must be one of INDUSTRY_CATALOG
 * @param {{taggedNewsItems: Array, reports: Array, kevIds: Set<string>}} sources
 */
export async function generateIndustryBriefing(industry, { taggedNewsItems, reports, kevIds }) {
  if (!INDUSTRY_CATALOG.includes(industry)) throw new Error(`Unknown industry: ${industry}`);

  const pool = poolForIndustry(industry, taggedNewsItems, reports, kevIds);
  if (pool.length < 3) throw new InsufficientCoverageError(industry);

  const groundingTable = buildGroundingTable(pool);
  const userMessage =
    `Industry: ${industry}\n\nSOURCE ARTICLE TABLE (cite by #):\n${groundingTable}\n\n` +
    `Generate the briefing JSON for this industry using ONLY what this table (and well-established category-level patterns) supports.`;

  let parsed;
  try {
    const response = await groqJson({
      model: GROQ_CHAT_MODEL,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userMessage },
      ],
      temperature: 0.3,
    });
    parsed = JSON.parse(response.message.content);
  } catch (error) {
    if (error instanceof GroqUnavailableError) throw error;
    throw new GroqUnavailableError(`failed to parse briefing response (${error.message})`);
  }

  return {
    industry,
    generatedAt: new Date().toISOString(),
    articleCount: pool.length,
    dateRangeDays: Math.round(POOL_WINDOW_MS / (24 * 60 * 60 * 1000)),
    executiveSummary: safeString(parsed.executiveSummary, "Insufficient grounded detail to produce an executive summary."),
    topEmergingThreats: safeTopEmergingThreats(parsed.topEmergingThreats, pool),
    activeThreatActors: safeActiveThreatActors(parsed.activeThreatActors, pool),
    emergingAttackTechniques: safeAttackTechniques(parsed.emergingAttackTechniques, pool),
    commonTargets: safeStringArray(parsed.commonTargets, 8),
    vulnerabilityTrends: { ...vulnerabilityTrendsFromPool(pool), commentary: safeString(parsed.vulnerabilityTrendsCommentary) },
    industryRiskAssessment: safeRiskAssessment(parsed.industryRiskAssessment),
    recommendedDefensivePriorities: safeStringArray(parsed.recommendedDefensivePriorities, 10),
    threatIntelOutlook: safeString(parsed.threatIntelOutlook, "Not enough grounded signal to project a reliable outlook."),
    references: pool.slice(0, MAX_REFERENCES).map(toArticleRef),
  };
}
