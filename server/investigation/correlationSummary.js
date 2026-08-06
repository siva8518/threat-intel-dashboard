// AI Correlation Summary -- reasons across a search's FULL unified result
// (graph edges, cross-referenced malware/actors/campaigns/reports, ranked
// findings, real industry data from matched AI Summarization reports), not
// just one graph node's direct edges the way graphInsights.js's "AI
// Investigation Summary" does. Answers the fixed set of questions an
// analyst actually asks when pivoting off any entity: what is this, why
// does it matter, which actors/campaigns/malware/victims/industries/ATT&CK
// techniques are involved, has the infrastructure been reused, what to
// investigate next.
//
// Same hybrid-grounding discipline as graphInsights.js and
// server/industryBriefing.js's mergeActorNarrative: every LIST of real
// entities (actors/campaigns/malware/victims/industries/techniques) is
// computed deterministically in JS from data this platform already has --
// the model is never asked to invent or reconstruct list membership from a
// JSON dump. The model's only job is narrative synthesis (what these
// findings mean together, why they matter, what to do next) over facts
// it's handed, exactly the same division of labor already proven
// throughout this app.
import { aiRouter } from "../ai/aiRouter.js";

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

/** Real per-industry relevance tallied across every matched AI Summarization report's own industryRelevance array (see server/aiThreatSummary.js) -- never inferred, never asked of the model. Only industries rated above "Low"/"Not Applicable" by at least one report are surfaced. */
function tallyIndustries(reports) {
  const byIndustry = new Map();
  const RANK = { Critical: 4, High: 3, Medium: 2, Low: 1, "Not Applicable": 0 };
  for (const report of reports) {
    for (const row of report.industryRelevance ?? []) {
      if (!row.industry || RANK[row.relevance] < 2) continue;
      const existing = byIndustry.get(row.industry);
      if (!existing || RANK[row.relevance] > RANK[existing.relevance]) {
        byIndustry.set(row.industry, { industry: row.industry, relevance: row.relevance, reportTitle: report.articleTitle });
      }
    }
  }
  return Array.from(byIndustry.values()).sort((a, b) => RANK[b.relevance] - RANK[a.relevance]);
}

/** Real infrastructure-reuse signal -- for an IOC-shaped search, sibling indicators from the same malware family (crossReference.js#crossReferenceIndicator's own computation) ARE reused infrastructure; for a name search, other IP/domain/hash graph edges beyond the primary entity are the same signal. Returns [] (not a guess) when nothing real supports it. */
function reuseIndicators(relatedIntelligence, graph) {
  const fromSiblings = (relatedIntelligence?.relatedIocs ?? []).map((i) => ({ indicator: i.indicator, indicatorType: i.indicatorType, malwareFamily: i.malwareFamily }));
  const fromGraph = (graph?.edges ?? [])
    .filter((e) => ["ip", "domain", "hash", "url"].includes(e.targetType))
    .map((e) => ({ indicator: e.targetKey, indicatorType: e.targetType, malwareFamily: null }));
  const seen = new Set();
  const out = [];
  for (const item of [...fromSiblings, ...fromGraph]) {
    const key = `${item.indicatorType}:${norm(item.indicator)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out.slice(0, 15);
}

const SYSTEM_PROMPT =
  "You are a senior Threat Intelligence Analyst producing a correlation summary for another analyst who just searched an indicator or entity in this platform. " +
  "You are given: the searched entity/indicator, its verdict, every REAL relationship this platform's Investigation Graph already discovered (ranked by confidence), which relationship types this platform genuinely cannot answer, real matched AI Summarization reports, real deterministically-tallied lists (industries affected, reused infrastructure, ATT&CK techniques, victims) -- these lists are already final and correct, you do NOT need to and must NOT re-derive or second-guess them. " +
  "Your job is narrative synthesis ONLY: explain what this entity is, why it matters, how the discovered relationships connect, and what to investigate next -- never restate the raw lists you were given, the analyst can already see them. " +
  "\n\nGROUNDING RULES:\n" +
  "- Every claim must trace to a specific item in the data you were given (an edge, a report, a tallied industry/reuse/technique entry). Never invent a name, a count, or a relationship not present in the data.\n" +
  '- If the data is too sparse to answer a question meaningfully, say so plainly (e.g. "Not enough discovered relationships to assess infrastructure reuse yet") rather than forcing an answer.\n' +
  '- Phrase "nextSteps" as direct, second-person analyst advice grounded in the actual data, e.g. "Pivot to <entity> next because <reason from the data>."\n' +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"whatIsThis": string -- 1-3 sentences identifying what the searched entity/indicator actually is, grounded in its verdict/summary/metadata.\n' +
  '"whyItMatters": string -- 2-4 sentences on why this matters to a defender right now, grounded in severity/confidence/relationships actually present.\n' +
  '"relationshipNarrative": string -- 2-4 sentences synthesizing what the discovered relationships mean TOGETHER (not a list of them) -- e.g. an actor-malware-campaign-infrastructure chain, or a plain statement that the relationships found so far don\'t form a coherent chain.\n' +
  '"infrastructureReuseAssessment": string -- 1-3 sentences on whether the reused-infrastructure list you were given indicates a real reuse pattern (shared across which entities) or is too thin to conclude anything; null is not allowed, say "No infrastructure reuse detected in this platform\'s current data" if the list is empty.\n' +
  '"nextSteps": string[] -- 2-6 direct, second-person recommended pivots/actions per the phrasing rule above, each grounded in a specific real entity or gap from the data.\n' +
  "No other text, no markdown formatting, no code fences.";

function safeString(value, fallback) {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}
function safeStringArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()) : [];
}
function parseModelReport(raw) {
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) return null;
  try {
    return JSON.parse(match[0]);
  } catch {
    return null;
  }
}

/**
 * @param {import("../../src/types/threat-intel.js").InvestigationResult} result
 */
export async function generateCorrelationSummary(result) {
  const { overview, graph, relatedIntelligence, rankedFindings, coverage } = result;

  const industriesAffected = tallyIndustries(relatedIntelligence?.matchingAiReports ?? []);
  const reusedInfrastructure = reuseIndicators(relatedIntelligence, graph);
  const attackTechniques = (graph?.edges ?? []).filter((e) => e.targetType === "attackTechnique").map((e) => ({ id: e.targetKey, name: e.targetLabel }));
  const victimsTargeted = (graph?.edges ?? []).filter((e) => e.targetType === "victim").map((e) => e.targetLabel);
  const relatedActors = (graph?.edges ?? []).filter((e) => e.targetType === "actor").map((e) => e.targetLabel);
  const relatedCampaigns = (graph?.edges ?? []).filter((e) => e.targetType === "campaign").map((e) => e.targetLabel);
  const relatedMalware = (graph?.edges ?? []).filter((e) => e.targetType === "malware").map((e) => e.targetLabel);

  const context = {
    entity: { type: overview.indicatorType, label: overview.indicator, verdict: overview.verdictLabel, severity: overview.severity, confidence: overview.confidence, found: graph?.node?.found ?? null, summary: graph?.node?.summary ?? null },
    topRankedRelationships: (rankedFindings ?? []).slice(0, 15).map((f) => ({ entity: f.label, type: f.entityType, relationship: f.relationship, confidenceScore: f.confidenceScore, reasoning: f.reasoning })),
    relationshipTypesWithNoDataSource: (graph?.unavailableRelationships ?? []).map((u) => ({ type: u.relationshipType, reason: u.reason })),
    searchCoverage: (coverage?.layers ?? []).map((l) => ({ layer: l.name, hitCount: l.hitCount })),
    industriesAffected,
    reusedInfrastructure,
    attackTechniques,
    victimsTargeted,
    relatedActors,
    relatedCampaigns,
    relatedMalware,
  };
  const userPrompt = `UNIFIED INVESTIGATION RESULT (verified by this platform, not model-generated):\n${JSON.stringify(context, null, 2)}\n\nProduce the JSON correlation summary described in your instructions.`;

  const response = await aiRouter.summarizeJson(userPrompt, { systemPrompt: SYSTEM_PROMPT, temperature: 0.3 });
  const parsed = parseModelReport(response.summary);
  if (!parsed) throw new Error("AI Correlation Summary: model response was not valid JSON");

  return {
    whatIsThis: safeString(parsed.whatIsThis, "Not enough data to characterize this entity."),
    whyItMatters: safeString(parsed.whyItMatters, "Not enough data to assess significance."),
    relationshipNarrative: safeString(parsed.relationshipNarrative, "No coherent relationship pattern found in the discovered data."),
    infrastructureReuseAssessment: safeString(parsed.infrastructureReuseAssessment, "No infrastructure reuse detected in this platform's current data."),
    nextSteps: safeStringArray(parsed.nextSteps),
    // Deterministic, real lists -- pass-through, never model-authored.
    industriesAffected,
    reusedInfrastructure,
    attackTechniques,
    victimsTargeted,
    relatedActors,
    relatedCampaigns,
    relatedMalware,
    model: response.model,
    provider: response.provider,
    generatedAt: new Date().toISOString(),
  };
}
