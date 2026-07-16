// Turns one vendor/CISA advisory article into a full enterprise-grade SOC
// threat intelligence report -- built for Tier 1/2/3 analysts, incident
// responders, threat hunters, detection engineers, security architects, and
// leadership, not a news summary. Same hybrid-grounding philosophy as the
// rest of this app (see server/newsCorrelation.js, server/githubIntel/enrich.js):
// facts this app can already verify (CVE IDs, KEV/EPSS status, severity, raw
// IOCs pulled from the article's own text) are extracted with proven
// regex/lookup logic, never trusted to the model's own recall -- this is
// also the mechanism that actually enforces the "never invent IOCs" rule
// below, not just a prompt instruction. The local LLM is only asked for the
// parts that genuinely require synthesis: narrative analysis, attack-chain
// reconstruction, detection/hunting/IR guidance, and its own self-assessed
// confidence/risk scoring.
import { ollamaJson } from "./rag/ollamaClient.js";
import { OLLAMA_CHAT_MODEL } from "./rag/config.js";
import { extractEntities } from "./githubIntel/extractor.js";

const SYSTEM_PROMPT =
  "You are a Principal Cyber Threat Intelligence Analyst supporting an enterprise SOC, Detection Engineering, Incident Response, Threat Hunting, and Security Leadership. " +
  "Your objective is NOT to summarize the article -- it is to transform it into operational intelligence a security team can immediately act on. Never copy the article's own wording. Never use vendor marketing language. Never invent IOCs, CVE IDs, or facts not stated or reasonably inferable from the article -- if something isn't reported, say exactly \"Not Reported\" for that field rather than guessing. Clearly keep confirmed information separate from your own inference. " +
  "If the article discusses an actively exploited vulnerability, prioritize in this order when allocating detail: (1) Detection, (2) Hunting, (3) Patch guidance, (4) Business impact. " +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys (all string fields: use \"Not Reported\" if the article doesn't support an answer; all array fields: use [] if none apply -- never pad with generic filler):\n" +
  '"aiSummarizationBullets": array of 5-10 short strings -- the operationally important facts only, no marketing language.\n' +
  '"executiveSummary": 2-4 sentences in business language covering the attack/vulnerability, exploitation status, and urgency.\n' +
  '"businessImpact": {"businessRisk": string, "operationalDisruption": string, "likelihoodOfExploitation": string, "industriesCommonlyTargeted": string[], "impactIfUnpatched": string}.\n' +
  '"threatOverview": {"attackChain": string (1-2 sentence overview), "initialAccess": string|null, "privilegeEscalation": string|null, "execution": string|null, "persistence": string|null, "defenseEvasion": string|null, "lateralMovement": string|null, "commandAndControl": string|null, "dataTheft": string|null, "ransomwareDeployment": string|null} -- null (not "Not Reported") for any stage not described in the article; do not fabricate a kill chain the article doesn\'t support.\n' +
  '"affectedProducts": {"products": string[], "versions": string[], "operatingSystems": string[], "cloudServices": string[], "applications": string[]} -- exactly as named in the article.\n' +
  '"vendorSeverityAssessment": {"vendorSeverity": string, "activeExploitation": string, "overallSocPriority": "Critical"|"High"|"Medium"|"Low"} -- CVSS/EPSS/KEV status is supplied separately from verified data, don\'t restate it here; vendorSeverity is the vendor\'s own stated severity rating (e.g. "Critical" per SonicWall), not your own guess.\n' +
  '"mitreAttack": array of {"technique": string, "techniqueId": "T1234" or null, "reason": string (why this technique applies, grounded in what the article describes), "killChainPhase": string}.\n' +
  '"threatActors": array of {"group": string, "aliases": string[], "motivation": string|null, "targetSectors": string[], "geography": string|null, "knownCampaigns": string[]} -- only actors explicitly named in the article.\n' +
  '"malware": array of {"family": string, "capabilities": string[], "persistence": string|null, "payload": string|null, "deliveryMechanism": string|null} -- only malware explicitly named in the article.\n' +
  '"detectionOpportunities": array of concrete, specific things a defender should monitor (log sources, event IDs, telemetry, behavioral signatures) -- grounded in this specific attack, not a generic checklist.\n' +
  '"threatHuntingOpportunities": {"defenderXdrKql": string[], "sentinelKql": string[], "splunkSpl": string[], "elastic": string[], "sigma": string[], "yara": string[], "crowdstrikeFalcon": string[], "carbonBlack": string[]} -- realistic hunting logic specific to this attack\'s actual behavior, not generic boilerplate queries; [] for any platform where you can\'t produce something genuinely specific to this attack.\n' +
  '"detectionEngineeringOpportunities": {"newAnalytics": string[], "newCorrelationRules": string[], "newSigmaRules": string[], "newKqlDetections": string[], "edrBehavioralDetections": string[], "siemCorrelationLogic": string[], "mitreCoverageGaps": string[], "telemetryGaps": string[], "logSourceRequirements": string[]}.\n' +
  '"incidentResponseGuidance": {"immediateTriageSteps": string[], "evidenceToCollect": string[], "containmentActions": string[], "forensicArtifacts": string[], "recoveryActions": string[], "validationSteps": string[]}.\n' +
  '"immediateRecommendations": {"critical": string[], "high": string[], "medium": string[], "low": string[]} -- each a concrete action, short-term mitigations and long-term hardening both welcome, sorted into the right priority bucket.\n' +
  '"patchInformationNarrative": {"availability": string, "fixedVersions": string[], "temporaryMitigations": string[], "vendorGuidance": string|null, "knownWorkarounds": string[]}.\n' +
  '"confidenceAssessment": {"level": "High"|"Medium"|"Low", "reasoning": string} -- your confidence this report accurately reflects the source article.\n' +
  '"aiRiskScoring": {"score": integer 0-100, "priority": "Critical"|"High"|"Medium"|"Low", "reasoning": string} -- build the score by adding: active exploitation +20, ransomware usage +15, public PoC +15, internet-exposed service +15, privilege escalation +10, authentication bypass +15, critical CVSS +10, widely deployed software +10; subtract points if exploitation requires unlikely conditions. Explain which factors applied.\n' +
  '"socAnalystTakeaway": one paragraph answering "If I am an L1/L2 analyst coming on shift, what should I immediately look for?"\n' +
  '"detectionEngineerTakeaway": one paragraph -- what detections should be created or improved.\n' +
  '"threatHunterTakeaway": one paragraph -- what hypotheses should be investigated.\n' +
  '"executiveLeadershipTakeaway": under 100 words, the business risk with zero technical jargon.\n' +
  "No other text, no markdown formatting, no code fences.";

function safeArray(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()) : [];
}

function safeString(value, fallback = "Not Reported") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function safeNullableString(value) {
  return typeof value === "string" && value.trim() ? value : null;
}

const SOC_PRIORITIES = new Set(["Critical", "High", "Medium", "Low"]);
function safePriority(value) {
  return SOC_PRIORITIES.has(value) ? value : "Medium";
}

const CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low"]);
function safeConfidenceLevel(value) {
  return CONFIDENCE_LEVELS.has(value) ? value : "Low";
}

function safeBusinessImpact(v) {
  v ??= {};
  return {
    businessRisk: safeString(v.businessRisk),
    operationalDisruption: safeString(v.operationalDisruption),
    likelihoodOfExploitation: safeString(v.likelihoodOfExploitation),
    industriesCommonlyTargeted: safeArray(v.industriesCommonlyTargeted),
    impactIfUnpatched: safeString(v.impactIfUnpatched),
  };
}

function safeThreatOverview(v) {
  v ??= {};
  return {
    attackChain: safeString(v.attackChain),
    initialAccess: safeNullableString(v.initialAccess),
    privilegeEscalation: safeNullableString(v.privilegeEscalation),
    execution: safeNullableString(v.execution),
    persistence: safeNullableString(v.persistence),
    defenseEvasion: safeNullableString(v.defenseEvasion),
    lateralMovement: safeNullableString(v.lateralMovement),
    commandAndControl: safeNullableString(v.commandAndControl),
    dataTheft: safeNullableString(v.dataTheft),
    ransomwareDeployment: safeNullableString(v.ransomwareDeployment),
  };
}

function safeAffectedProducts(v) {
  v ??= {};
  return {
    products: safeArray(v.products),
    versions: safeArray(v.versions),
    operatingSystems: safeArray(v.operatingSystems),
    cloudServices: safeArray(v.cloudServices),
    applications: safeArray(v.applications),
  };
}

function safeVendorSeverityAssessment(v) {
  v ??= {};
  return {
    vendorSeverity: safeString(v.vendorSeverity),
    activeExploitation: safeString(v.activeExploitation),
    overallSocPriority: safePriority(v.overallSocPriority),
  };
}

function safeMitreArray(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.technique === "string")
    .map((v) => ({
      technique: v.technique,
      techniqueId: typeof v.techniqueId === "string" ? v.techniqueId : null,
      reason: safeString(v.reason),
      killChainPhase: safeString(v.killChainPhase),
    }));
}

function safeThreatActors(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.group === "string" && v.group.trim())
    .map((v) => ({
      group: v.group,
      aliases: safeArray(v.aliases),
      motivation: safeNullableString(v.motivation),
      targetSectors: safeArray(v.targetSectors),
      geography: safeNullableString(v.geography),
      knownCampaigns: safeArray(v.knownCampaigns),
    }));
}

function safeMalware(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.family === "string" && v.family.trim())
    .map((v) => ({
      family: v.family,
      capabilities: safeArray(v.capabilities),
      persistence: safeNullableString(v.persistence),
      payload: safeNullableString(v.payload),
      deliveryMechanism: safeNullableString(v.deliveryMechanism),
    }));
}

function safeHuntingOpportunities(v) {
  v ??= {};
  return {
    defenderXdrKql: safeArray(v.defenderXdrKql),
    sentinelKql: safeArray(v.sentinelKql),
    splunkSpl: safeArray(v.splunkSpl),
    elastic: safeArray(v.elastic),
    sigma: safeArray(v.sigma),
    yara: safeArray(v.yara),
    crowdstrikeFalcon: safeArray(v.crowdstrikeFalcon),
    carbonBlack: safeArray(v.carbonBlack),
  };
}

function safeDetectionEngineering(v) {
  v ??= {};
  return {
    newAnalytics: safeArray(v.newAnalytics),
    newCorrelationRules: safeArray(v.newCorrelationRules),
    newSigmaRules: safeArray(v.newSigmaRules),
    newKqlDetections: safeArray(v.newKqlDetections),
    edrBehavioralDetections: safeArray(v.edrBehavioralDetections),
    siemCorrelationLogic: safeArray(v.siemCorrelationLogic),
    mitreCoverageGaps: safeArray(v.mitreCoverageGaps),
    telemetryGaps: safeArray(v.telemetryGaps),
    logSourceRequirements: safeArray(v.logSourceRequirements),
  };
}

function safeIncidentResponse(v) {
  v ??= {};
  return {
    immediateTriageSteps: safeArray(v.immediateTriageSteps),
    evidenceToCollect: safeArray(v.evidenceToCollect),
    containmentActions: safeArray(v.containmentActions),
    forensicArtifacts: safeArray(v.forensicArtifacts),
    recoveryActions: safeArray(v.recoveryActions),
    validationSteps: safeArray(v.validationSteps),
  };
}

function safeImmediateRecommendations(v) {
  v ??= {};
  return {
    critical: safeArray(v.critical),
    high: safeArray(v.high),
    medium: safeArray(v.medium),
    low: safeArray(v.low),
  };
}

function safePatchInformation(v) {
  v ??= {};
  return {
    availability: safeString(v.availability),
    fixedVersions: safeArray(v.fixedVersions),
    temporaryMitigations: safeArray(v.temporaryMitigations),
    vendorGuidance: safeNullableString(v.vendorGuidance),
    knownWorkarounds: safeArray(v.knownWorkarounds),
  };
}

function safeConfidenceAssessment(v) {
  v ??= {};
  return { level: safeConfidenceLevel(v.level), reasoning: safeString(v.reasoning) };
}

function safeAiRiskScoring(v) {
  v ??= {};
  const n = Number(v.score);
  return {
    score: Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : null,
    priority: safePriority(v.priority),
    reasoning: safeString(v.reasoning),
  };
}

function parseModelReport(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!parsed || typeof parsed !== "object") return null;
    return {
      aiSummarizationBullets: safeArray(parsed.aiSummarizationBullets),
      executiveSummary: safeString(parsed.executiveSummary),
      businessImpact: safeBusinessImpact(parsed.businessImpact),
      threatOverview: safeThreatOverview(parsed.threatOverview),
      affectedProducts: safeAffectedProducts(parsed.affectedProducts),
      vendorSeverityAssessment: safeVendorSeverityAssessment(parsed.vendorSeverityAssessment),
      mitreAttack: safeMitreArray(parsed.mitreAttack),
      threatActors: safeThreatActors(parsed.threatActors),
      malware: safeMalware(parsed.malware),
      detectionOpportunities: safeArray(parsed.detectionOpportunities),
      threatHuntingOpportunities: safeHuntingOpportunities(parsed.threatHuntingOpportunities),
      detectionEngineeringOpportunities: safeDetectionEngineering(parsed.detectionEngineeringOpportunities),
      incidentResponseGuidance: safeIncidentResponse(parsed.incidentResponseGuidance),
      immediateRecommendations: safeImmediateRecommendations(parsed.immediateRecommendations),
      patchInformationNarrative: safePatchInformation(parsed.patchInformationNarrative),
      confidenceAssessment: safeConfidenceAssessment(parsed.confidenceAssessment),
      aiRiskScoring: safeAiRiskScoring(parsed.aiRiskScoring),
      socAnalystTakeaway: safeString(parsed.socAnalystTakeaway),
      detectionEngineerTakeaway: safeString(parsed.detectionEngineerTakeaway),
      threatHunterTakeaway: safeString(parsed.threatHunterTakeaway),
      executiveLeadershipTakeaway: safeString(parsed.executiveLeadershipTakeaway),
    };
  } catch {
    return null; // model returned malformed JSON -- treat as "couldn't generate," not a guess
  }
}

// Only the IOC types this app can extract with proven, regex-verified logic
// (server/githubIntel/extractor.js, already used elsewhere in this app) are
// populated -- mutex names, registry keys, scheduled tasks, services, user
// agents, certificates etc. have no reliable extraction path from prose news
// text, so rather than ask the model to fabricate them (directly violating
// the "never invent IOCs" rule), those categories are always reported empty.
// Sigma/YARA/Suricata/Snort are DETECTION CONTENT, not indicators -- those
// come from the model's own threatHuntingOpportunities/detectionEngineering
// fields instead, where drafting rule logic from described behavior is
// legitimate analyst work, not invented evidence.
const IOC_CATEGORY_BY_TYPE = {
  ipv4: "ipAddresses",
  ipv6: "ipAddresses",
  domains: "domains",
  urls: "urls",
  sha256: "hashes",
  sha1: "hashes",
  md5: "hashes",
  emails: "emailAddresses",
};

function extractIocs(text) {
  const extracted = extractEntities(text, {});
  const categories = { ipAddresses: [], domains: [], urls: [], hashes: [], emailAddresses: [] };
  for (const [type, category] of Object.entries(IOC_CATEGORY_BY_TYPE)) {
    for (const value of extracted[type] ?? []) categories[category].push(value);
  }
  return categories;
}

/**
 * @param {object} article - {title, summary, link, source, publishedDate}
 * @param {object} grounded - already-verified per-article facts from server/newsCorrelation.js#tagNewsItems
 * @param {string[]} grounded.cveIds
 * @param {string} grounded.severity - uppercase Severity ("CRITICAL"/"HIGH"/"MEDIUM"/"LOW")
 * @param {object} grounded.cveEnrichment - cveId -> {severity, cvssScore, knownExploited, epssScore, sourceUrl}
 */
export async function generateThreatSummary(article, grounded) {
  const sourceText = `${article.title}\n${article.summary ?? ""}`;
  const iocs = extractIocs(sourceText);

  const cveContext = grounded.cveIds
    .map((id) => {
      const c = grounded.cveEnrichment?.[id];
      return `${id}: CVSS ${c?.cvssScore ?? "unknown"}, KEV ${c?.knownExploited ? "yes" : "no"}, EPSS ${c?.epssScore ?? "unknown"}`;
    })
    .join("; ");

  const userContent =
    `Source: ${article.source}\nHeadline: ${article.title}\n` +
    (article.summary ? `Summary: ${article.summary}\n` : "") +
    (cveContext ? `Verified CVE data for this article (use this, don't restate or contradict it): ${cveContext}\n` : "") +
    `Overall severity already computed for this article: ${grounded.severity}\n`;

  const response = await ollamaJson("/api/chat", {
    model: OLLAMA_CHAT_MODEL,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: userContent },
    ],
    // This report is far larger than this app's other LLM calls (25+
    // sections, several with per-platform hunting-query arrays) -- confirmed
    // live that Ollama's default context window is small enough to risk
    // silently truncating a response this size mid-generation, which then
    // fails JSON parsing entirely. Widened well past what this prompt +
    // article + expected output should ever need.
    options: { temperature: 0.2, num_ctx: 16384 },
  });

  const modelReport = parseModelReport(response.message?.content ?? "");
  if (!modelReport) return null;

  return {
    id: article.link,
    articleTitle: article.title,
    articleLink: article.link,
    articleSource: article.source,
    publishedDate: article.publishedDate,
    generatedAt: new Date().toISOString(),
    severity: grounded.severity,
    cves: grounded.cveIds.map((id) => grounded.cveEnrichment?.[id] ?? { id, severity: "UNKNOWN", cvssScore: null, knownExploited: false, epssScore: null, sourceUrl: `https://nvd.nist.gov/vuln/detail/${id}` }),
    iocs,
    references: [
      { label: article.source, url: article.link },
      ...grounded.cveIds.map((id) => ({ label: id, url: `https://nvd.nist.gov/vuln/detail/${id}` })),
    ],
    ...modelReport,
  };
}
