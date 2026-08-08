// On-demand, per-industry deep-dive threat briefing -- reached by clicking
// "Generate Full Briefing" on an Industry Heatmap row, or from the
// Industry Intelligence page's selector (see server/emergingThreatsRanking.js,
// which computes that same heatmap and whose matchIndustries()/INDUSTRY_CATALOG
// this module reuses rather than duplicating). Generated live per request,
// not scheduled/cached, since most of the 14 sectors won't be viewed in a
// given session -- see the "on-demand per industry" placement decision.
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
import { aiRouter, AllProvidersFailedError } from "./ai/aiRouter.js";
import { AI_TASK } from "./ai/aiTasks.js";
import { INDUSTRY_CATALOG } from "./aiThreatSummary.js";
import { matchIndustries } from "./emergingThreatsRanking.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "./threatActorIntelligence.js";
import { buildEntityHuntingQueries } from "./huntingLibrary.js";
import { rankActorsForIndustry, rankMalwareForIndustry, rankCampaignsForIndustry, iocEligibleMalwareNames } from "./industryCorrelation.js";
import * as cache from "./cache.js";

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
// tie-break when tacticsSummary ranks by observed count. Kept in sync with
// server/correlate.js's own ATTACK_TACTICS_ORDER, the authoritative list --
// confirmed live against the real bundle that the classic 14-tactic model
// (single "Defense Evasion") is stale: the live Enterprise matrix splits
// that into "Defense Impairment" and "Stealth" instead, a 15-tactic list.
const TACTIC_DISPLAY = new Map([
  ["reconnaissance", "Reconnaissance"],
  ["resource development", "Resource Development"],
  ["initial access", "Initial Access"],
  ["execution", "Execution"],
  ["persistence", "Persistence"],
  ["privilege escalation", "Privilege Escalation"],
  ["defense impairment", "Defense Impairment"],
  ["stealth", "Stealth"],
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
    const keywordHit = matchIndustries(item.title).includes(industry);
    const reportHit = reportRow && (reportRow.relevance === "Critical" || reportRow.relevance === "High");
    if (!keywordHit && !reportHit) continue;

    const cveIds = item.tags?.cveIds ?? [];
    matched.push({
      id: item.link,
      title: item.title,
      // Not sent to the model (buildGroundingTable stays title-only, to keep
      // the prompt small) -- kept only for selectCandidateTechniques below,
      // whose keyword scoring is otherwise blind to anything not literally
      // in a headline. See its own comment for why that mattered live.
      summary: item.summary ?? "",
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
// selectCandidateTechniques -- scored against every article's title+summary
// in the pool combined (an industry briefing spans many articles, not one),
// so the model gets a short, plausible, real-ID candidate list instead of
// free-associating from ~700 techniques' worth of training memory.
// Title-only was confirmed live to under-match: technique names (e.g.
// "Phishing", "Process Injection") show up far more in a source's own
// summary/dek than in a punchy headline, and aiThreatSummary.js's own
// per-article version already scores title+summary -- this brings the
// multi-article version in line with that, not a new scope.
function selectCandidateTechniques(pool, techniques) {
  const words = new Set(
    pool
      .map((a) => `${a.title} ${a.summary}`.toLowerCase())
      .join(" ")
      .match(/[a-z0-9]{4,}/g) ?? [],
  );
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
  '"industryRiskAssessment": {"currentThreatLevel": "Critical"|"High"|"Medium"|"Low", "whyTargeted": string (2-3 sentences on why THIS sector specifically is being targeted right now, grounded in the table -- what makes it attractive/vulnerable, e.g. legacy OT exposure, high-value data, low security maturity, regulatory pressure creating urgency to pay), "mostLikelyAttackScenarios": string[] (2-4), "highestBusinessRisks": string[] (2-4), "technologiesRequiringAttention": string[] (2-5)}.\n' +
  '"recommendedDefensivePriorities": string[] of up to 10 items security teams should prioritize over the NEXT 30 DAYS specifically, ranked most urgent first, specific to this industry and this table -- not generic best-practices, not a multi-quarter roadmap.\n' +
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

const NO_DETAIL_FALLBACK = "Not enough article-level detail in this platform's corpus for this sector specifically -- see this entity's full profile in Threat Actor/Malware Intelligence.";
const TIER_TO_CONFIDENCE = { direct: "High", "cross-linked": "Medium", historical: "Low" };

/**
 * Left-joins the model's own (already-shape-validated) narrative onto the
 * deterministic, real ranked actor list from industryCorrelation.js -- every
 * ranked actor survives even when the model wrote nothing about it (using
 * real entity data as fallback text), instead of the old behavior of
 * silently dropping any actor the model's own JSON didn't happen to name.
 */
function mergeActorNarrative(rankedActors, value, pool) {
  const modelByName = new Map();
  for (const raw of Array.isArray(value) ? value : []) {
    if (typeof raw?.actor === "string" && raw.actor.trim()) modelByName.set(norm(raw.actor), raw);
  }

  return rankedActors.map(({ entity, tier, confidenceScore, reason }) => {
    const m = modelByName.get(norm(entity.name)) ?? entity.aliases.map((a) => modelByName.get(norm(a))).find(Boolean);
    const sources = groundedArticles(m?.sourceArticleIds, pool);
    return {
      actor: entity.name,
      country: m ? safeNullableString(m.country) : entity.country,
      confidence: CONFIDENCE_LEVELS.has(m?.confidence) ? m.confidence : TIER_TO_CONFIDENCE[tier],
      motivation: m ? safeString(m.motivation, NO_DETAIL_FALLBACK) : entity.motivations?.length ? entity.motivations.join(", ") : NO_DETAIL_FALLBACK,
      typicalTargets: m ? safeString(m.typicalTargets, NO_DETAIL_FALLBACK) : NO_DETAIL_FALLBACK,
      recentCampaigns: m ? safeString(m.recentCampaigns, NO_DETAIL_FALLBACK) : entity.malwareUsed?.length ? `Associated with ${entity.malwareUsed.slice(0, 3).join(", ")}.` : NO_DETAIL_FALLBACK,
      ttps: m ? safeString(m.ttps, NO_DETAIL_FALLBACK) : entity.techniqueIds?.length ? `${entity.techniqueIds.length} MITRE ATT&CK technique(s) on record for this actor.` : NO_DETAIL_FALLBACK,
      sourceArticles: sources.map(toArticleRef),
      reportCount: entity.mentionCount ?? sources.length,
      firstSeen: entity.firstSeen ?? null,
      lastSeen: entity.lastSeen ?? null,
      tier,
      confidenceScore,
      correlationReason: reason,
    };
  });
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

// Cheap keyword classifier over a malware entity's own real ATT&CK-sourced
// description -- used only as a fallback `type` when the model didn't
// independently describe this family (malwareIntelligence.js entities carry
// no structured `type` field of their own). Defaults to "Malware" when
// nothing matches, never invents a more specific type than the text supports.
function inferMalwareType(entity) {
  const text = (entity.description ?? "").toLowerCase();
  if (text.includes("ransomware")) return "Ransomware";
  if (text.includes("stealer")) return "Stealer";
  if (text.includes("loader") || text.includes("downloader")) return "Loader";
  if (text.includes("banking trojan") || text.includes("banking malware")) return "Banking Trojan";
  if (text.includes("trojan")) return "Trojan";
  if (text.includes("backdoor")) return "Backdoor";
  if (text.includes("botnet") || text.includes("bot ")) return "Botnet";
  if (text.includes("wiper")) return "Wiper";
  if (text.includes("remote access") || /\brat\b/.test(text)) return "RAT";
  return "Malware";
}

/** Left-joins the model's own narrative onto the deterministic, real ranked malware list from industryCorrelation.js -- same "never drop a real ranked entity just because the model didn't independently name it" discipline as mergeActorNarrative above. */
function mergeMalwareNarrative(rankedMalware, value, pool) {
  const modelByName = new Map();
  for (const raw of Array.isArray(value) ? value : []) {
    if (typeof raw?.name === "string" && raw.name.trim()) modelByName.set(norm(raw.name), raw);
  }

  return rankedMalware.map(({ entity, tier, confidenceScore, reason }) => {
    const m = modelByName.get(norm(entity.name)) ?? entity.aliases.map((a) => modelByName.get(norm(a))).find(Boolean);
    const sources = groundedArticles(m?.sourceArticleIds, pool);
    return {
      name: entity.name,
      type: m ? safeString(m.type, inferMalwareType(entity)) : inferMalwareType(entity),
      primaryPurpose: m ? safeString(m.primaryPurpose, entity.description ?? NO_DETAIL_FALLBACK) : (entity.description ?? NO_DETAIL_FALLBACK),
      initialInfectionMethod: m ? safeString(m.initialInfectionMethod, NO_DETAIL_FALLBACK) : NO_DETAIL_FALLBACK,
      persistenceMechanism: m ? safeString(m.persistenceMechanism, NO_DETAIL_FALLBACK) : NO_DETAIL_FALLBACK,
      commonPayload: m ? safeString(m.commonPayload, NO_DETAIL_FALLBACK) : NO_DETAIL_FALLBACK,
      typicalVictims: m ? safeString(m.typicalVictims, NO_DETAIL_FALLBACK) : NO_DETAIL_FALLBACK,
      severity: RELEVANCE_LEVELS.has(m?.severity) ? m.severity : "Medium",
      trend: computeTrend(sources),
      sourceArticles: sources.map(toArticleRef),
      tier,
      confidenceScore,
      correlationReason: reason,
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
    whyTargeted: safeString(v.whyTargeted, "Not enough grounded detail to explain why this sector is currently targeted."),
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

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

/**
 * Real CVSS/EPSS/KEV per CVE ID in the grounding pool -- looked up from the
 * same bulk NVD sync cache + EPSS + KEV sources server/routes/dashboard.js's
 * own /dashboard/cves route already reads, never a live per-CVE network call
 * (too slow for a request-scoped multi-CVE lookup). A CVE too new/old for
 * the bulk NVD sync gets KEV-only enrichment -- honest, not fabricated.
 */
function criticalCvesForPool(pool) {
  const nvdRecords = cache.getEntry("nvd").data?.latestCves?.records ?? [];
  const nvdById = new Map(nvdRecords.map((r) => [r.id, r]));
  const kevIds = new Set((cache.getEntry("cisa-kev").data?.entries ?? []).map((e) => e.cveId));
  const epssScores = cache.getEntry("epss").data ?? {};

  const seen = new Set();
  const out = [];
  for (const a of pool) {
    for (const cveId of a.cveIds) {
      if (seen.has(cveId)) continue;
      seen.add(cveId);
      const record = nvdById.get(cveId);
      out.push({
        cveId,
        cvssScore: record?.cvssScore ?? null,
        epssScore: epssScores[cveId]?.score ?? null,
        epssPercentile: epssScores[cveId]?.percentile ?? null,
        knownExploited: kevIds.has(cveId),
        description: record?.description ?? null,
      });
    }
  }
  return out
    .sort((x, y) => Number(y.knownExploited) - Number(x.knownExploited) || (y.epssScore ?? 0) - (x.epssScore ?? 0) || (y.cvssScore ?? 0) - (x.cvssScore ?? 0))
    .slice(0, 20);
}

/**
 * Real ip/domain/url/hash IOCs from this industry's already-validated
 * malware families' own tracked indicators (server/malwareIntelligence.js's
 * iocs/articleIocs -- same fields server/investigation/investigationGraph.js
 * already reads), plus real email addresses from the pool's own matched AI
 * Summarization reports. `names` is broadened beyond the shown malwareFamilies
 * cards to include malware used by a direct-tier actor for this industry (see
 * industryCorrelation.js#iocEligibleMalwareNames) -- a real actor<->malware
 * link still surfaces indicators even when the malware family itself had no
 * direct sector text match. Deterministic, capped, deduped.
 */
function buildIndustryIocFeed(names, pool, reports) {
  const entities = getMalwareEntities().filter((e) => names.has(norm(e.name)));

  const indicators = [];
  const seen = new Set();
  outer: for (const entity of entities) {
    for (const ioc of [...(entity.iocs ?? []), ...(entity.articleIocs ?? [])]) {
      const key = `${ioc.indicatorType}:${norm(ioc.indicator)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      indicators.push({ indicator: ioc.indicator, indicatorType: ioc.indicatorType, malwareFamily: entity.name, firstSeen: ioc.firstSeen ?? null });
      if (indicators.length >= 175) break outer;
    }
  }

  const poolIds = new Set(pool.map((a) => a.id));
  for (const report of reports) {
    if (!poolIds.has(report.id)) continue;
    for (const email of report.iocs?.emailAddresses ?? []) {
      const key = `email:${norm(email)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      indicators.push({ indicator: email, indicatorType: "email", malwareFamily: null, firstSeen: report.publishedDate ?? null });
      if (indicators.length >= 200) break;
    }
  }

  return { indicators, totalCount: indicators.length };
}

/** The pool's own matched entries that are backed by a real stored AiThreatSummaryReport (report.id === article link, see aiThreatSummary.js) -- not just a bare news item -- exposing real vendor/severity/actor/campaign/AI-summary fields already on the stored report, never re-authored. */
function recentReportsForPool(pool, reports) {
  const reportsById = new Map(reports.map((r) => [r.id, r]));
  const out = [];
  for (const a of pool) {
    const report = reportsById.get(a.id);
    if (!report) continue;
    out.push({
      id: report.id,
      articleTitle: report.articleTitle,
      articleLink: report.articleLink,
      articleSource: report.articleSource,
      publishedDate: report.publishedDate,
      severity: report.severity,
      threatActors: (report.threatActors ?? []).map((t) => t.group),
      campaignName: report.campaignName ?? null,
      executiveSummary: report.executiveSummary ?? null,
    });
    if (out.length >= 20) break;
  }
  return out;
}

/**
 * Real per-platform detection queries + rule citations for this industry's
 * validated malware + actor entities -- pure reuse of
 * server/huntingLibrary.js#buildEntityHuntingQueries (already powers the
 * Hunting & Detection tab), just scoped down to this industry's own
 * entities instead of every tracked one. No new query-generation logic.
 */
function detectionAndHuntingForIndustry(malwareFamilies, activeThreatActors) {
  const ruleIndex = cache.getEntry("detection-rules").data?.index ?? [];
  const malwareNames = new Set(malwareFamilies.map((m) => norm(m.name)));
  const actorNames = new Set(activeThreatActors.map((a) => norm(a.actor)));

  const malwareEntities = getMalwareEntities().filter((e) => malwareNames.has(norm(e.name)));
  const actorEntities = getActorEntities().filter((e) => actorNames.has(norm(e.name)) || (e.aliases ?? []).some((al) => actorNames.has(norm(al))));

  const items = buildEntityHuntingQueries(malwareEntities, actorEntities, ruleIndex);
  const DETECTION_PLATFORMS = { sentinelKql: "sentinelKql", defenderXdrKql: "sentinelKql", splunkSpl: "splunkSpl", elastic: "elastic", sigma: "sigma", yara: "yara" };

  const detectionOpportunities = { sentinelKql: [], splunkSpl: [], elastic: [], sigma: [], yara: [] };
  const huntingOpportunities = [];
  for (const item of items) {
    const entry = { platform: item.platformLabel, query: item.query, source: item.articleSource, sourceUrl: item.articleLink, malware: item.malware, threatActors: item.threatActors };
    const bucket = DETECTION_PLATFORMS[item.platform];
    if (bucket && detectionOpportunities[bucket].length < 10) detectionOpportunities[bucket].push(entry);
    if (huntingOpportunities.length < 30) huntingOpportunities.push(entry);
  }
  return { detectionOpportunities, huntingOpportunities };
}

/**
 * @param {string} industry - must be one of INDUSTRY_CATALOG
 * @param {{taggedNewsItems: Array, reports: Array, kevIds: Set<string>, attackTechniques?: Array}} sources
 * @param {Array} [sources.attackTechniques] - this app's synced MITRE ATT&CK technique catalog, {id, name, tactic}[] (see server/connectors/attack.js) -- optional; topAttackTechniques/tacticsSummary come back empty without it rather than erroring.
 */
function buildKnownEntitiesBlock(rankedActors, rankedMalware) {
  if (rankedActors.length === 0 && rankedMalware.length === 0) return "";
  const actorLines = rankedActors.map((r) => r.entity.name).join(", ");
  const malwareLines = rankedMalware.map((r) => r.entity.name).join(", ");
  return (
    "\n\nKNOWN RELEVANT ENTITIES (real actors/malware this platform has already correlated to this industry -- " +
    "write real, specific narrative detail (motivation/typicalTargets/recentCampaigns/ttps, or type/primaryPurpose/etc.) " +
    "for as many of these as the table above genuinely supports; it is fine to describe one briefly even with thin table coverage " +
    "as long as you don't invent specifics beyond what's grounded -- these names do not need to appear in the table to be included):\n" +
    (actorLines ? `Actors: ${actorLines}\n` : "") +
    (malwareLines ? `Malware: ${malwareLines}` : "")
  );
}

export async function generateIndustryBriefing(industry, { taggedNewsItems, reports, kevIds, attackTechniques = [] }) {
  if (!INDUSTRY_CATALOG.includes(industry)) throw new Error(`Unknown industry: ${industry}`);

  const pool = poolForIndustry(industry, taggedNewsItems, reports, kevIds);
  if (pool.length < 3) throw new InsufficientCoverageError(industry);

  // Deterministic, real, tiered/confidence-scored correlation -- computed
  // BEFORE the model call and independent of the (much smaller) article pool
  // above, so Active Threat Actors / Active Campaigns / Trending Malware /
  // the IOC feed stay populated from this platform's full entity stores and
  // ransomware-disclosure data even when this industry's own news pool is
  // thin. See server/industryCorrelation.js for the tiering rationale.
  const rankedActors = rankActorsForIndustry(industry);
  const rankedMalware = rankMalwareForIndustry(industry, rankedActors);
  const rankedCampaigns = rankCampaignsForIndustry(industry, rankedActors, rankedMalware);

  const candidateTechniques = selectCandidateTechniques(pool, attackTechniques);
  const validTechniqueIds = new Set(attackTechniques.map((t) => t.id));
  const idToTechnique = new Map(attackTechniques.map((t) => [t.id, t]));

  const groundingTable = buildGroundingTable(pool);
  const userMessage =
    `Industry: ${industry}\n\nSOURCE ARTICLE TABLE (cite by #):\n${groundingTable}\n\n` +
    `${buildTechniqueCandidatesBlock(candidateTechniques)}` +
    `${buildKnownEntitiesBlock(rankedActors, rankedMalware)}\n\n` +
    `Generate the briefing JSON for this industry using ONLY what this table (and well-established category-level patterns) supports.`;

  let parsed;
  try {
    const response = await aiRouter.summarizeJson(userMessage, { systemPrompt: SYSTEM_PROMPT, temperature: 0.3, task: AI_TASK.INDUSTRY_INTELLIGENCE });
    parsed = JSON.parse(response.summary);
  } catch (error) {
    if (error instanceof AllProvidersFailedError) throw error;
    throw new Error(`failed to parse briefing response (${error.message})`);
  }

  const topAttackTechniques = safeTopAttackTechniques(parsed.topAttackTechniques, pool, validTechniqueIds, idToTechnique);
  const activeThreatActors = mergeActorNarrative(rankedActors, parsed.activeThreatActors, pool);
  const malwareFamilies = mergeMalwareNarrative(rankedMalware, parsed.malwareFamilies, pool);
  const { detectionOpportunities, huntingOpportunities } = detectionAndHuntingForIndustry(malwareFamilies, activeThreatActors);

  return {
    industry,
    generatedAt: new Date().toISOString(),
    articleCount: pool.length,
    dateRangeDays: Math.round(POOL_WINDOW_MS / (24 * 60 * 60 * 1000)),
    executiveSummary: safeString(parsed.executiveSummary, "Insufficient grounded detail to produce an executive summary."),
    topEmergingThreats: safeTopEmergingThreats(parsed.topEmergingThreats, pool),
    activeThreatActors,
    activeCampaigns: rankedCampaigns,
    emergingAttackTechniques: safeAttackTechniques(parsed.emergingAttackTechniques, pool),
    topAttackTechniques,
    tacticsSummary: computeTacticsSummary(topAttackTechniques),
    malwareFamilies,
    commonTargets: safeStringArray(parsed.commonTargets, 8),
    vulnerabilityTrends: { ...vulnerabilityTrendsFromPool(pool), commentary: safeString(parsed.vulnerabilityTrendsCommentary) },
    criticalCves: criticalCvesForPool(pool),
    industryIocFeed: buildIndustryIocFeed(iocEligibleMalwareNames(rankedMalware, rankedActors), pool, reports),
    recentReports: recentReportsForPool(pool, reports),
    detectionOpportunities,
    huntingOpportunities,
    industryRiskAssessment: safeRiskAssessment(parsed.industryRiskAssessment),
    recommendedDefensivePriorities: safeStringArray(parsed.recommendedDefensivePriorities, 10),
    threatIntelOutlook: safeString(parsed.threatIntelOutlook, "Not enough grounded signal to project a reliable outlook."),
    references: pool.slice(0, MAX_REFERENCES).map(toArticleRef),
  };
}
