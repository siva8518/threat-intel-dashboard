// AI Investigation Summary -- analyzes an already-computed Investigation
// Graph node (server/investigation/investigationGraph.js) and synthesizes
// what the relationships MEAN, instead of restating them. Fired
// automatically the moment a Workspace search's relationships finish
// loading (see src/hooks/useInvestigationWorkspace.ts) -- unlike
// server/investigationAi.js's deep report, which stays manual-trigger-only
// by deliberate design (that one is a heavier, broader narrative; this one
// is scoped tightly to "what does this specific graph imply").
//
// Same hybrid-grounding discipline as investigationAi.js: every countable
// fact (report overlap, infrastructure reuse) is tallied in JS before the
// model ever sees it, so the model's job is narration/judgment, not
// counting -- reduces hallucination risk on exactly the kind of claim
// ("these 3 reports all mention this actor") that's cheap to get wrong.
import { aiRouter } from "../ai/aiRouter.js";
import { getReportById } from "../aiThreatSummaryStore.js";
import { crossReferenceIndicator } from "./crossReference.js";

const INFRA_TYPES = new Set(["ip", "domain", "url", "hash"]);
const MAX_INFRA_CHECKED = 20;

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

/** Tallies which malware/actor/campaign names appear in 2+ of the AI Summarization reports connected to this graph (via its `report`-type edges), and how many reports each infrastructure edge (ip/domain/url/hash) independently appears in -- real, computed facts for the model to narrate, not invent. */
function buildReportOverlap(edges) {
  const reportIds = edges.filter((e) => e.targetType === "report").map((e) => e.targetKey);
  const reports = reportIds.map((id) => getReportById(id)).filter(Boolean);

  function tally(getValues) {
    const byKey = new Map();
    for (const r of reports) {
      for (const v of getValues(r)) {
        if (!v) continue;
        const key = norm(v);
        if (!byKey.has(key)) byKey.set(key, { value: v, reportTitles: [] });
        byKey.get(key).reportTitles.push(r.articleTitle);
      }
    }
    return Array.from(byKey.values()).filter((e) => e.reportTitles.length >= 2);
  }

  const infraEdges = edges.filter((e) => INFRA_TYPES.has(e.targetType)).slice(0, MAX_INFRA_CHECKED);
  const infrastructureReportCounts = infraEdges
    .map((e) => ({ indicator: e.targetKey, indicatorType: e.targetType, reportCount: crossReferenceIndicator(e.targetKey).matchingAiReports.length }))
    .filter((e) => e.reportCount > 0);

  return {
    reportsConsidered: reports.map((r) => ({ id: r.id, title: r.articleTitle, source: r.articleSource, publishedDate: r.publishedDate, severity: r.severity, malware: (r.malware ?? []).map((m) => m.family), threatActors: (r.threatActors ?? []).map((a) => a.group), campaignName: r.campaignName ?? null, cves: (r.cves ?? []).map((c) => c.id) })),
    overlappingMalware: tally((r) => (r.malware ?? []).map((m) => m.family)),
    overlappingActors: tally((r) => (r.threatActors ?? []).map((a) => a.group)),
    overlappingCampaigns: tally((r) => (r.campaignName ? [r.campaignName] : [])),
    infrastructureReportCounts,
  };
}

const SYSTEM_PROMPT =
  "You are a senior Threat Intelligence Analyst reviewing an automated investigation graph a junior analyst just pulled up. " +
  "You are given the investigated entity, every real relationship (edge) already discovered for it, which relationship types have no data source (so you never suggest investigating something this platform simply cannot answer), and pre-computed overlap facts (which malware/actor/campaign names already appear in 2+ of the connected reports, and how many reports each piece of infrastructure independently appears in). " +
  "The edge list may span multiple pivots the analyst has already made (a multi-hop graph), not only the investigated entity's own direct connections -- treat every edge as real discovered intelligence regardless of how many hops away it sits, and never assume everything is one hop from the entity. " +
  "Do NOT restate the edge list -- the analyst can already see it in full above your summary. Your job is to explain what it MEANS: which connections matter, what they imply together, and what to do next. " +
  "\n\nGROUNDING RULES:\n" +
  "- Every claim must trace to a specific edge, report, or tally entry you were given. Name the actual entity/report/count, never a vague generality.\n" +
  '- Only claim an attack chain, a "strongest" actor match, or a cross-report pattern when the provided data actually supports it. When it doesn\'t, say so plainly (e.g. "No coherent attack chain can be inferred from the relationships discovered so far" or a null field, per the schema below) -- a forced or invented answer is worse than an honest gap.\n' +
  "- Use the overlap tallies exactly as given (reportsConsidered / overlappingMalware / overlappingActors / overlappingCampaigns / infrastructureReportCounts) for any claim about multiple reports, campaigns, or reused infrastructure -- do not estimate or invent a count yourself.\n" +
  '- Phrase every entry in "recommendations" as direct, second-person analyst advice, e.g. "You should also investigate <entity> because <reason>.", "This IP shares infrastructure with <N> other indicators from the same malware family.", "This malware family has recently been observed with <actor/campaign>.", "These campaigns frequently appear together in the same reporting." Ground each one in the provided data.\n' +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"summary": string -- 2-4 sentences synthesizing what this entity\'s relationships mean together, not a list of them.\n' +
  '"standoutRelationships": string[] -- 0-6 short lines on which specific relationships matter most and why, citing the actual related entity.\n' +
  '"likelyAttackChain": string | null -- one sentence describing a plausible attack chain ONLY if the discovered relationships genuinely support one (e.g. actor -> malware -> infrastructure -> campaign all connect); null if the graph is too sparse.\n' +
  '"strongestActorMatch": {"name": string, "reasoning": string} | null -- the single best-attributed threat actor and why, grounded in the edges; null if no actor edge exists at all.\n' +
  '"priorityInvestigationTargets": [{"entity": string, "entityType": string, "reasoning": string}] -- 0-5 specific related entities (by exact name/value and graph node type) that deserve immediate follow-up, most important first.\n' +
  '"crossReportPatterns": string[] -- 0-6 lines describing real overlap found in the provided tallies (shared malware/actors/campaigns across reports, reused infrastructure) -- [] if the tallies show no real overlap.\n' +
  '"recommendations": string[] -- 2-6 direct, second-person analyst-advisory lines per the phrasing rule above.\n' +
  "No other text, no markdown formatting, no code fences.";

function safeArray(value) {
  return Array.isArray(value) ? value.filter((v) => v !== null && v !== undefined) : [];
}
function safeString(value) {
  return typeof value === "string" && value.trim() ? value : null;
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
 * @param {{node: object, edges: object[], unavailableRelationships: object[], overview: object}} payload
 */
export async function generateGraphInsights({ node, edges, unavailableRelationships, overview }) {
  const overlap = buildReportOverlap(edges);
  const context = {
    entity: { type: node.type, label: node.label, summary: node.summary, found: node.found },
    overview: overview ?? null,
    relationships: edges.map((e) => ({ targetType: e.targetType, target: e.targetLabel, relationship: e.relationship, why: e.why, confidence: e.confidence, firstSeen: e.firstSeen, lastSeen: e.lastSeen, sources: e.sources })),
    relationshipTypesWithNoDataSource: (unavailableRelationships ?? []).map((u) => ({ type: u.relationshipType, reason: u.reason })),
    ...overlap,
  };
  const userPrompt = `INVESTIGATION GRAPH (verified by this platform, not model-generated):\n${JSON.stringify(context, null, 2)}\n\nProduce the JSON analysis described in your instructions for this entity's relationships.`;

  const result = await aiRouter.summarizeJson(userPrompt, { systemPrompt: SYSTEM_PROMPT, temperature: 0.3 });
  const parsed = parseModelReport(result.summary);
  if (!parsed) throw new Error("AI Investigation Summary: model response was not valid JSON");

  const actorMatch = parsed.strongestActorMatch && typeof parsed.strongestActorMatch === "object" ? { name: safeString(parsed.strongestActorMatch.name) ?? "", reasoning: safeString(parsed.strongestActorMatch.reasoning) ?? "" } : null;

  return {
    summary: safeString(parsed.summary) ?? "No synthesis available.",
    standoutRelationships: safeStringArray(parsed.standoutRelationships),
    likelyAttackChain: safeString(parsed.likelyAttackChain),
    strongestActorMatch: actorMatch && actorMatch.name ? actorMatch : null,
    priorityInvestigationTargets: safeArray(parsed.priorityInvestigationTargets)
      .filter((t) => t && typeof t === "object" && safeString(t.entity))
      .map((t) => ({ entity: safeString(t.entity), entityType: safeString(t.entityType) ?? "name", reasoning: safeString(t.reasoning) ?? "" })),
    crossReportPatterns: safeStringArray(parsed.crossReportPatterns),
    recommendations: safeStringArray(parsed.recommendations),
    model: result.model,
    provider: result.provider,
    generatedAt: new Date().toISOString(),
  };
}
