// On-demand AI Investigation Report for the Intelligence Investigation
// Console -- "Generate AI Report" button only (never fired automatically on
// search, see the plan this was built from). Same hybrid-grounding
// philosophy as server/aiThreatSummary.js: every fact the backend can
// already verify (verdict, severity, related actors/malware/CVEs, raw
// lookup data) is handed to the model as context, never re-derived by it;
// the model is only asked for genuine synthesis -- narrative, attacker-
// objective judgment, business impact, confidence framing, investigation
// path, containment recommendation, the 6 role-specific operational
// guidance blocks, and detection-opportunity ideas.
import { aiRouter } from "./ai/aiRouter.js";

const SYSTEM_PROMPT =
  "You are a Tier 3 SOC analyst investigating a single indicator (IP/domain/URL/hash/CVE/threat actor/malware family/campaign/other artifact) for a fellow analyst who just pasted it into an investigation console. " +
  "You are given the indicator, its detected type, and every fact this platform has already verified about it (verdict, severity, related actors/malware/campaigns, raw source data). Do not restate that data verbatim -- synthesize it into judgment. Never invent a fact not present in what you were given -- if the provided data doesn't support an answer, say \"Not Reported\" or \"Insufficient data\" for that field rather than guessing. " +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"whatThisIs": string -- 1-2 sentences plainly stating what this indicator represents, grounded only in the provided data.\n' +
  '"whyItMatters": string -- 1-3 sentences on why this specific indicator matters operationally, given its verdict/severity/relationships.\n' +
  '"likelyAttackerObjective": string -- your best-supported judgment of what an attacker using this indicator is likely trying to achieve (e.g. initial access, C2, data theft, ransomware staging) -- "Not Reported" if the data gives no basis for this.\n' +
  '"businessImpact": string -- 1-2 sentences on the operational/business consequence if this indicator is confirmed active in an environment.\n' +
  '"confidenceReasoning": string -- one sentence explaining your confidence in this assessment, grounded in how much corroborating data was actually provided.\n' +
  '"recommendedInvestigationPath": string[] -- an ordered list of 3-6 concrete next steps an analyst should take, most important first.\n' +
  '"immediateContainmentRecommendations": string[] -- 0-5 concrete containment actions, [] if the verdict doesn\'t warrant containment (e.g. a clean/unknown indicator).\n' +
  '"operationalGuidance": {"socAnalyst": string, "threatHunter": string, "threatIntel": string, "detectionEngineer": string, "incidentResponse": string, "vulnerabilityManagement": string} -- one role-specific paragraph each, answering "what should this role specifically do with this indicator". vulnerabilityManagement should be "Not Applicable -- no CVE associated with this indicator" when the indicator isn\'t a CVE and no CVE was provided in context.\n' +
  '"detectionOpportunities": {"sentinelKql": string[], "sigma": string[], "splunkSpl": string[], "elastic": string[], "yara": string[], "detectionGaps": string[], "huntingHypotheses": string[]} -- specific query/rule CONCEPTS for this exact indicator (name the field/table/logic, not a full rule body), [] for any platform genuinely not applicable (e.g. yara only applies to file hashes).\n' +
  "No other text, no markdown formatting, no code fences.";

function safeArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()) : [];
}
function safeString(value, fallback = "Not Reported") {
  return typeof value === "string" && value.trim() ? value : fallback;
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

/** Trims an investigation result down to what's worth handing the model as context -- raw per-source blobs are large and mostly redundant with the overview, so only the parts that add real signal are included. */
function buildContext(investigation) {
  const { indicator, type, overview, moduleData, relatedIntelligence } = investigation;
  return {
    indicator,
    type,
    verdict: overview.overallVerdict,
    verdictLabel: overview.verdictLabel,
    severity: overview.severity,
    riskLevel: overview.riskLevel,
    confidence: overview.confidence,
    firstSeen: overview.firstSeen,
    lastSeen: overview.lastSeen,
    activeCampaigns: overview.activeCampaigns,
    associatedThreatActors: overview.associatedThreatActors,
    mitreAttackMapping: overview.mitreAttackMapping,
    relatedIntelligence,
    moduleSummary: summarizeModuleData(type, moduleData),
  };
}

function summarizeModuleData(type, moduleData) {
  if (type === "cve") {
    return {
      cve: moduleData.cve ? { severity: moduleData.cve.severity, cvssScore: moduleData.cve.cvssScore, epssScore: moduleData.cve.epssScore, knownExploited: moduleData.cve.knownExploited, description: moduleData.cve.description, vendor: moduleData.cve.vendor, product: moduleData.cve.product } : null,
      relatedActors: moduleData.profile?.relatedActors?.map((a) => a.name) ?? [],
      relatedMalware: moduleData.profile?.relatedMalware ?? [],
      exploits: moduleData.profile?.exploits?.length ?? 0,
    };
  }
  if (type === "name") {
    return {
      malware: moduleData.malware?.map((m) => ({ name: m.entity.name, verified: m.entity.verified, iocSightings: m.entity.iocSightings })) ?? [],
      actors: moduleData.actors?.map((a) => ({ name: a.name, type: a.type, verified: a.verified, motivations: a.motivations })) ?? [],
      campaigns: moduleData.campaigns?.map((c) => ({ name: c.name, verified: c.verified })) ?? [],
    };
  }
  if (moduleData.noExternalSource) {
    return { noExternalSource: true, note: moduleData.note };
  }
  // ip/domain/url/hash: a compact digest of the source breakdown, not the full raw payload
  return {
    sourceCount: moduleData.lookupResults?.length ?? 0,
    sources: (moduleData.lookupResults ?? []).map((r) => ({ source: r.source, verdict: r.verdict })),
    network: moduleData.network ?? undefined,
    security: moduleData.security ?? undefined,
    behavior: moduleData.behavior ?? undefined,
    detection: moduleData.detection ?? undefined,
  };
}

/**
 * @param {import("./investigation/index.js").InvestigationResult} investigation
 */
export async function generateInvestigationAiReport(investigation) {
  const context = buildContext(investigation);
  const userPrompt = `INDICATOR CONTEXT (verified by this platform, not model-generated):\n${JSON.stringify(context, null, 2)}\n\nProduce the JSON report described in your instructions for this indicator.`;

  const result = await aiRouter.summarizeJson(userPrompt, { systemPrompt: SYSTEM_PROMPT, temperature: 0.3 });
  const parsed = parseModelReport(result.summary);
  if (!parsed) throw new Error("AI Investigation Report: model response was not valid JSON");

  const og = parsed.operationalGuidance ?? {};
  const det = parsed.detectionOpportunities ?? {};

  return {
    whatThisIs: safeString(parsed.whatThisIs),
    whyItMatters: safeString(parsed.whyItMatters),
    likelyAttackerObjective: safeString(parsed.likelyAttackerObjective),
    businessImpact: safeString(parsed.businessImpact),
    confidenceReasoning: safeString(parsed.confidenceReasoning),
    recommendedInvestigationPath: safeArray(parsed.recommendedInvestigationPath),
    immediateContainmentRecommendations: safeArray(parsed.immediateContainmentRecommendations),
    operationalGuidance: {
      socAnalyst: safeString(og.socAnalyst),
      threatHunter: safeString(og.threatHunter),
      threatIntel: safeString(og.threatIntel),
      detectionEngineer: safeString(og.detectionEngineer),
      incidentResponse: safeString(og.incidentResponse),
      vulnerabilityManagement: safeString(og.vulnerabilityManagement),
    },
    detectionOpportunities: {
      sentinelKql: safeArray(det.sentinelKql),
      sigma: safeArray(det.sigma),
      splunkSpl: safeArray(det.splunkSpl),
      elastic: safeArray(det.elastic),
      yara: safeArray(det.yara),
      detectionGaps: safeArray(det.detectionGaps),
      huntingHypotheses: safeArray(det.huntingHypotheses),
    },
    model: result.model,
    provider: result.provider,
    generatedAt: new Date().toISOString(),
  };
}
