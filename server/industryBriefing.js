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
const MAX_TECHNIQUE_CANDIDATES = 40; // keyword-scored slice of the full ~600-technique ATT&CK catalog handed to the model, same purpose as aiThreatSummary.js's own candidate list
const SEVERITY_RANK = { critical: 3, high: 2, medium: 1, low: 0 };

// server/connectors/attack.js derives each technique's tactic from STIX
// kill_chain_phases (e.g. "command-and-control" -> "command and control"
// after the dash replace) -- mapped to the canonical Enterprise ATT&CK
// tactic names for display. Order here is kill-chain order, used as the
// tie-break when tacticsSummary ranks by observed count.
const TACTIC_DISPLAY = new Map([
  ["initial access", "Initial Access"],
  ["execution", "Execution"],
  ["persistence", "Persistence"],
  ["privilege escalation", "Privilege Escalation"],
  ["defense evasion", "Defense Evasion"],
  ["credential access", "Credential Access"],
  ["discovery", "Discovery"],
  ["lateral movement", "Lateral Movement"],
  ["collection", "Collection"],
  ["command and control", "Command & Control"],
  ["exfiltration", "Exfiltration"],
  ["impact", "Impact"],
]);

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
  // The underlying news pool can legitimately contain the same link twice
  // (a source syncing the same advisory into more than one feed category --
  // confirmed live via a React key-collision warning on a duplicated CISA
  // ICS advisory) -- same dedupe-by-link fix already applied to
  // buildEmergingThreatsRanking() in emergingThreatsRanking.js, needed here
  // too since `id` (the link) is this pool's identity for citations/keys.
  const seenLinks = new Set();

  for (const item of taggedNewsItems) {
    if (seenLinks.has(item.link)) continue;
    seenLinks.add(item.link);

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

// Keyword-overlap scoring against this app's own synced MITRE ATT&CK catalog
// (server/connectors/attack.js), same philosophy as aiThreatSummary.js's
// selectCandidateTechniques -- scored against every article's title in the
// pool combined (an industry briefing spans many articles, not one), so the
// model gets a short, plausible, real-ID candidate list instead of free-
// associating from ~600 techniques' worth of training memory.
function selectCandidateTechniques(pool, techniques) {
  const words = new Set(pool.map((a) => a.title.toLowerCase()).join(" ").match(/[a-z0-9]{4,}/g) ?? []);
  if (words.size === 0 || !techniques.length) return [];
  const scored = [];
  for (const t of techniques) {
    const nameWords = t.name.toLowerCase().match(/[a-z0-9]{4,}/g) ?? [];
    const score = nameWords.filter((w) => words.has(w)).length;
    if (score > 0) scored.push({ t, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, MAX_TECHNIQUE_CANDIDATES).map((s) => s.t);
}

function buildTechniqueCandidatesBlock(candidates) {
  if (candidates.length === 0) {
    return "CANDIDATE MITRE ATT&CK TECHNIQUES: none pre-matched this industry's coverage. Set techniqueId to null for every entry in topAttackTechniques unless certain of a real, well-known technique ID -- never invent one.";
  }
  const lines = candidates.map((t) => `${t.id} -- ${t.name} (${t.tactic})`).join("\n");
  return `CANDIDATE MITRE ATT&CK TECHNIQUES (techniqueId in topAttackTechniques must be copied exactly from this list, or null if none genuinely apply):\n${lines}`;
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
  '"activeThreatActors": array of {"actor": string (must be an actor name that literally appears in the table\'s actor list), "country": string or null (only if this actor\'s national attribution is well-established and widely reported -- null if unattributed or uncertain, never guess), "confidence": "High"|"Medium"|"Low" (your confidence in this actor genuinely targeting this sector, based on how directly the table supports it), "motivation": string, "typicalTargets": string, "recentCampaigns": string, "ttps": string, "sourceArticleIds": int[]} -- [] if the table names no actors for this industry, do not invent one.\n' +
  '"emergingAttackTechniques": array of {"technique": string (e.g. "AI-assisted phishing", "ClickFix", "Cloud identity attacks", "Supply chain attacks" -- only ones genuinely evidenced by the table or a well-known category-level pattern relevant to this industry), "whyIncreasing": string, "sourceArticleIds": int[]}.\n' +
  '"topAttackTechniques": array of 5-10 {"techniqueId": string or null, "techniqueName": string, "whyUsed": string (why attackers use this technique against this sector specifically), "exampleScenario": string (a concrete example attack scenario using this technique against this sector, grounded in the table or a well-established pattern), "detectionPriority": "Critical"|"High"|"Medium", "sourceArticleIds": int[]} -- techniqueId MUST be copied exactly from the CANDIDATE MITRE ATT&CK TECHNIQUES list in the user message, or null if none genuinely apply; never invent an ID. Rank most prevalent/significant first. This is distinct from emergingAttackTechniques above -- that field is broad technique CATEGORIES/trends, this field is specific, real, ID-mapped MITRE ATT&CK techniques.\n' +
  '"malwareFamilies": array of {"name": string (must be a malware family name that literally appears in the table\'s malware list), "type": string (one of "Ransomware", "Loader", "Banking Trojan", "Stealer", "RAT", "Botnet", "Wiper", "Backdoor", or another concise type if none fit), "primaryPurpose": string, "initialInfectionMethod": string, "persistenceMechanism": string, "commonPayload": string, "typicalVictims": string, "severity": "Critical"|"High"|"Medium"|"Low", "sourceArticleIds": int[]} -- [] if the table names no malware for this industry, do not invent one. Do not include "trend" -- computed separately from your citations.\n' +
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
const CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low"]);
const DETECTION_PRIORITY_LEVELS = new Set(["Critical", "High", "Medium"]);

function safeNullableString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

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
      country: safeNullableString(t.country),
      confidence: CONFIDENCE_LEVELS.has(t.confidence) ? t.confidence : "Medium",
      motivation: safeString(t.motivation, "Not stated in available reporting"),
      typicalTargets: safeString(t.typicalTargets, "Not stated in available reporting"),
      recentCampaigns: safeString(t.recentCampaigns, "Not stated in available reporting"),
      ttps: safeString(t.ttps, "Not stated in available reporting"),
      sourceArticles: groundedArticles(t.sourceArticleIds, pool).map(toArticleRef),
    }));
}

/** techniqueId validated against the real synced ATT&CK catalog (validTechniqueIds), never trusted from the model -- an invented/near-miss ID is dropped to null rather than shown as real. */
function safeTopAttackTechniques(value, pool, validTechniqueIds, idToTechnique) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 10).map((t) => {
    const techniqueId = typeof t?.techniqueId === "string" && validTechniqueIds.has(t.techniqueId.toUpperCase()) ? t.techniqueId.toUpperCase() : null;
    const catalogEntry = techniqueId ? idToTechnique.get(techniqueId) : null;
    return {
      techniqueId,
      // Prefer the catalog's own real name when we have a validated ID, over trusting the model's own transcription of it.
      techniqueName: catalogEntry?.name ?? safeString(t?.techniqueName, "Unnamed technique"),
      tactic: catalogEntry ? (TACTIC_DISPLAY.get(catalogEntry.tactic) ?? catalogEntry.tactic) : null,
      whyUsed: safeString(t?.whyUsed),
      exampleScenario: safeString(t?.exampleScenario),
      detectionPriority: DETECTION_PRIORITY_LEVELS.has(t?.detectionPriority) ? t.detectionPriority : "Medium",
      sourceArticles: groundedArticles(t?.sourceArticleIds, pool).map(toArticleRef),
    };
  });
}

/**
 * Deterministically derived from the already-validated topAttackTechniques'
 * own real `tactic` field -- never separately asked of the model, since
 * every technique already carries its real tactic from the synced ATT&CK
 * catalog. Ranked by how many of the briefing's own techniques touch each
 * tactic, tie-broken by kill-chain order (TACTIC_DISPLAY's insertion order).
 */
function computeTacticsSummary(topAttackTechniques) {
  const counts = new Map();
  for (const t of topAttackTechniques) {
    if (!t.tactic) continue;
    counts.set(t.tactic, (counts.get(t.tactic) ?? 0) + 1);
  }
  const order = [...TACTIC_DISPLAY.values()];
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || order.indexOf(a[0]) - order.indexOf(b[0]))
    .map(([tactic, techniqueCount]) => ({ tactic, techniqueCount }));
}

/** name validated against the pool's own tagged malware list -- an invented family name is dropped rather than shown as real. */
function safeMalwareFamilies(value, pool) {
  if (!Array.isArray(value)) return [];
  const knownMalware = new Set(pool.flatMap((a) => a.malware.map((n) => n.toLowerCase())));
  return value
    .filter((m) => typeof m?.name === "string" && knownMalware.has(m.name.toLowerCase()))
    .slice(0, 10)
    .map((m) => {
      const sources = groundedArticles(m.sourceArticleIds, pool);
      return {
        name: m.name.trim(),
        type: safeString(m.type, "Malware"),
        primaryPurpose: safeString(m.primaryPurpose, "Not stated in available reporting"),
        initialInfectionMethod: safeString(m.initialInfectionMethod, "Not stated in available reporting"),
        persistenceMechanism: safeString(m.persistenceMechanism, "Not stated in available reporting"),
        commonPayload: safeString(m.commonPayload, "Not stated in available reporting"),
        typicalVictims: safeString(m.typicalVictims, "Not stated in available reporting"),
        severity: RELEVANCE_LEVELS.has(m.severity) ? m.severity : "Medium",
        trend: computeTrend(sources),
        sourceArticles: sources.map(toArticleRef),
      };
    });
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
 * @param {{taggedNewsItems: Array, reports: Array, kevIds: Set<string>, attackTechniques?: Array}} sources
 * @param {Array} [sources.attackTechniques] - this app's synced MITRE ATT&CK technique catalog, {id, name, tactic}[] (see server/connectors/attack.js) -- optional; topAttackTechniques/tacticsSummary come back empty without it rather than erroring.
 */
export async function generateIndustryBriefing(industry, { taggedNewsItems, reports, kevIds, attackTechniques = [] }) {
  if (!INDUSTRY_CATALOG.includes(industry)) throw new Error(`Unknown industry: ${industry}`);

  const pool = poolForIndustry(industry, taggedNewsItems, reports, kevIds);
  if (pool.length < 3) throw new InsufficientCoverageError(industry);

  const candidateTechniques = selectCandidateTechniques(pool, attackTechniques);
  const validTechniqueIds = new Set(attackTechniques.map((t) => t.id));
  const idToTechnique = new Map(attackTechniques.map((t) => [t.id, t]));

  const groundingTable = buildGroundingTable(pool);
  const userMessage =
    `Industry: ${industry}\n\nSOURCE ARTICLE TABLE (cite by #):\n${groundingTable}\n\n` +
    `${buildTechniqueCandidatesBlock(candidateTechniques)}\n\n` +
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

  const topAttackTechniques = safeTopAttackTechniques(parsed.topAttackTechniques, pool, validTechniqueIds, idToTechnique);

  return {
    industry,
    generatedAt: new Date().toISOString(),
    articleCount: pool.length,
    dateRangeDays: Math.round(POOL_WINDOW_MS / (24 * 60 * 60 * 1000)),
    executiveSummary: safeString(parsed.executiveSummary, "Insufficient grounded detail to produce an executive summary."),
    topEmergingThreats: safeTopEmergingThreats(parsed.topEmergingThreats, pool),
    activeThreatActors: safeActiveThreatActors(parsed.activeThreatActors, pool),
    emergingAttackTechniques: safeAttackTechniques(parsed.emergingAttackTechniques, pool),
    topAttackTechniques,
    tacticsSummary: computeTacticsSummary(topAttackTechniques),
    malwareFamilies: safeMalwareFamilies(parsed.malwareFamilies, pool),
    commonTargets: safeStringArray(parsed.commonTargets, 8),
    vulnerabilityTrends: { ...vulnerabilityTrendsFromPool(pool), commentary: safeString(parsed.vulnerabilityTrendsCommentary) },
    industryRiskAssessment: safeRiskAssessment(parsed.industryRiskAssessment),
    recommendedDefensivePriorities: safeStringArray(parsed.recommendedDefensivePriorities, 10),
    threatIntelOutlook: safeString(parsed.threatIntelOutlook, "Not enough grounded signal to project a reliable outlook."),
    references: pool.slice(0, MAX_REFERENCES).map(toArticleRef),
  };
}
