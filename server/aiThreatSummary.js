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
import { detectionRulesFor } from "./correlate.js";

const SYSTEM_PROMPT =
  "You are a Principal Cyber Threat Intelligence Analyst supporting an enterprise SOC, Detection Engineering, Incident Response, Threat Hunting, and Security Leadership. " +
  "Your objective is NOT to summarize the article -- it is to transform it into operational intelligence a security team can immediately act on. Never copy the article's own wording. Never use vendor marketing language. Never invent IOCs, CVE IDs, or facts not stated or reasonably inferable from the article -- if something isn't reported, say exactly \"Not Reported\" for that field rather than guessing. Clearly keep confirmed information separate from your own inference. " +
  "This is a TECHNICAL EXTRACTION task, not an executive summary, for every field below except where a field is explicitly marked as business-language. Do not compress or abstract away technical specifics: if the article names a specific vulnerability class, attack technique, configuration setting, trigger, parameter, API, or mechanism, that exact name belongs in your output -- \"attackers abused GitHub Actions\" is not acceptable when the article says \"a pwn request vulnerability via a pull_request_target-triggered workflow, which runs in the context of the base repository with access to repository secrets.\" Preserve every exploitation technique, vulnerable component, attack prerequisite, configuration weakness, security implication, and defensive recommendation the researchers describe. " +
  "If the article discusses an actively exploited vulnerability, prioritize in this order when allocating detail: (1) Detection, (2) Hunting, (3) Patch guidance, (4) Business impact. " +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys (all string fields: use \"Not Reported\" if the article doesn't support an answer; all array fields: use [] if none apply -- never pad with generic filler):\n" +
  '"aiTechnicalSummary": {"threat": string[], "attackVector": string[], "rootCause": string[], "exploitationDetails": string[], "technicalFindings": string[], "securityImplications": string[], "detectionOpportunities": string[], "huntingOpportunities": string[], "immediateActions": string[]} -- the technical extraction described above, broken into these buckets: threat (what the vulnerability/attack actually is, named specifically); attackVector (the exact entry point/trigger/mechanism an attacker uses, e.g. the specific workflow trigger or API); rootCause (the underlying technical reason the flaw exists, e.g. a specific misconfiguration or design weakness and exactly what it grants); exploitationDetails (how exploitation actually proceeds, step by step, per the article); technicalFindings (other concrete technical facts from the research not covered above); securityImplications (concretely what an attacker gains and the blast radius); detectionOpportunities (a few of the most important concrete monitoring signals -- deeper platform-specific queries still belong in the detectionOpportunities/threatHuntingOpportunities fields further below, don\'t duplicate those here); huntingOpportunities (a few concrete hunting hypotheses/signals, same distinction); immediateActions (concrete, specific mitigations). Every bullet should read like it came from a technical researcher, not a press release -- name the specific thing, don\'t generalize it away.\n' +
  '"executiveSummary": 2-4 sentences in business language covering the attack/vulnerability, exploitation status, and urgency.\n' +
  '"businessImpact": {"businessRisk": string, "operationalDisruption": string, "likelihoodOfExploitation": string, "industriesCommonlyTargeted": string[], "impactIfUnpatched": string}.\n' +
  '"threatOverview": {"attackChain": string (1-2 sentence overview), "initialAccess": string|null, "privilegeEscalation": string|null, "execution": string|null, "persistence": string|null, "defenseEvasion": string|null, "lateralMovement": string|null, "commandAndControl": string|null, "dataTheft": string|null, "ransomwareDeployment": string|null} -- null (not "Not Reported") for any stage not described in the article; do not fabricate a kill chain the article doesn\'t support.\n' +
  '"affectedProducts": {"products": string[], "versions": string[], "operatingSystems": string[], "cloudServices": string[], "applications": string[]} -- exactly as named in the article.\n' +
  '"vendorSeverityAssessment": {"vendorSeverity": string, "activeExploitation": string, "overallSocPriority": "Critical"|"High"|"Medium"|"Low"} -- CVSS/EPSS/KEV status is supplied separately from verified data, don\'t restate it here; vendorSeverity is the vendor\'s own stated severity rating (e.g. "Critical" per SonicWall), not your own guess.\n' +
  '"mitreAttack": array of {"technique": string, "techniqueId": string or null, "reason": string (why this technique applies, grounded in what the article describes), "killChainPhase": string} -- techniqueId MUST be copied exactly from the CANDIDATE MITRE ATT&CK TECHNIQUES list in the user message, or null if none genuinely apply. Never invent a technique ID that isn\'t in that list, even if it looks plausible.\n' +
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
  '"threatIntelTakeaway": one paragraph -- what a CTI/Threat Intelligence team should do with this: attribution and campaign tracking, correlating this activity/actor/malware against existing intelligence holdings, watching for related infrastructure or TTPs reappearing elsewhere, and who internally needs this disseminated.\n' +
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

// Matches an optional immediately-adjacent paren pair too, so a mention the
// model already wrote as "Name (T1234)" doesn't get double-wrapped into
// "Name (Name (T1234))" -- captured separately so the replacer can tell the
// two shapes apart. Deliberately no \s* around the paren/ID -- an earlier
// version had that and it silently ate legitimate word-separating
// whitespace between unrelated matches (e.g. turned "T1204.002, T1204.001"
// into "...002),Malicious..." by swallowing the space after the comma).
const TECHNIQUE_MENTION_PATTERN = /(\()?\b(T\d{4}(?:\.\d{3})?)\b(\))?/gi;

// Same grounding principle as safeMitreArray further down, extended to
// free-text fields it never touches (aiTechnicalSummary's bullets, threatOverview's
// kill-chain-stage strings) -- confirmed live the model sometimes leaks a
// bare technique-ID token into these narrative fields instead of an actual
// description (e.g. threatOverview.initialAccess coming back as literally
// "T1689" rather than prose). Real IDs get annotated with their real name
// for readability; anything that doesn't match the synced catalog is
// stripped rather than left as an unverifiable claim embedded in prose.
function groundTechniqueMentions(text, validTechniqueIds, idToTechniqueName) {
  if (typeof text !== "string" || !text.trim()) return text;
  const grounded = text.replace(TECHNIQUE_MENTION_PATTERN, (_match, openParen, idPart, closeParen) => {
    const id = idPart.toUpperCase();
    const wasParenthesized = Boolean(openParen && closeParen);
    if (!validTechniqueIds.has(id)) return "";
    if (wasParenthesized) return `(${id})`; // model already supplied its own name right before this -- don't re-annotate
    const name = idToTechniqueName.get(id);
    return name ? `${name} (${id})` : id;
  });
  return grounded
    .replace(/\(\s*\)/g, "")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+([,.;:])/g, "$1")
    .trim();
}

function safeNullableGroundedString(value, validTechniqueIds, idToTechniqueName) {
  const str = safeNullableString(value);
  if (!str) return null;
  const grounded = groundTechniqueMentions(str, validTechniqueIds, idToTechniqueName);
  return grounded || null;
}

function groundedBullets(values, validTechniqueIds, idToTechniqueName) {
  return safeArray(values)
    .map((v) => groundTechniqueMentions(v, validTechniqueIds, idToTechniqueName))
    .filter((v) => v && v.trim());
}

function safeAiTechnicalSummary(v, validTechniqueIds, idToTechniqueName) {
  v ??= {};
  const ground = (values) => groundedBullets(values, validTechniqueIds, idToTechniqueName);
  return {
    threat: ground(v.threat),
    attackVector: ground(v.attackVector),
    rootCause: ground(v.rootCause),
    exploitationDetails: ground(v.exploitationDetails),
    technicalFindings: ground(v.technicalFindings),
    securityImplications: ground(v.securityImplications),
    detectionOpportunities: ground(v.detectionOpportunities),
    huntingOpportunities: ground(v.huntingOpportunities),
    immediateActions: ground(v.immediateActions),
  };
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

function safeThreatOverview(v, validTechniqueIds, idToTechniqueName) {
  v ??= {};
  const ground = (val) => safeNullableGroundedString(val, validTechniqueIds, idToTechniqueName);
  return {
    attackChain: safeString(v.attackChain),
    initialAccess: ground(v.initialAccess),
    privilegeEscalation: ground(v.privilegeEscalation),
    execution: ground(v.execution),
    persistence: ground(v.persistence),
    defenseEvasion: ground(v.defenseEvasion),
    lateralMovement: ground(v.lateralMovement),
    commandAndControl: ground(v.commandAndControl),
    dataTheft: ground(v.dataTheft),
    ransomwareDeployment: ground(v.ransomwareDeployment),
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

const TECHNIQUE_ID_SHAPE = /^T\d{4}(\.\d{3})?$/i;

// validTechniqueIds/techniqueNameToId/idToTechniqueName come from this app's
// own synced MITRE ATT&CK catalog (server/connectors/attack.js) -- the model
// is asked to only choose from a candidate subset in the prompt
// (buildTechniqueCandidatesBlock below), but this validates whatever
// actually comes back regardless of whether the model followed that
// instruction, the same "verify, don't trust recall" pattern used for
// CVEs/severity/IOCs elsewhere in this app. Confirmed live this catches two
// distinct failure modes: (1) outright fabrication -- a report once
// returned "T1042.003" for a supply-chain technique, which is factually
// wrong (T1042 is "Change Default File Association"); (2) field-swapping --
// a later report put a genuinely correct ID ("T1213.002", SharePoint data
// collection) into the `technique` (name) field instead of `techniqueId`,
// which the ID-only check above would have silently missed.
function safeMitreArray(value, validTechniqueIds, techniqueNameToId, idToTechniqueName) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => v && typeof v === "object" && typeof v.technique === "string")
    .map((v) => {
      let techniqueName = v.technique.trim();
      let rawId = typeof v.techniqueId === "string" ? v.techniqueId.trim().toUpperCase() : null;

      // Detect the model having swapped the two fields: `technique` holds
      // something shaped like "T1234" or "T1234.567" rather than a name.
      // Only trust it if it's also a real ID -- shape alone isn't enough.
      if (TECHNIQUE_ID_SHAPE.test(techniqueName)) {
        const candidateId = techniqueName.toUpperCase();
        if (validTechniqueIds.has(candidateId)) {
          rawId = candidateId;
          techniqueName = idToTechniqueName.get(candidateId) ?? techniqueName;
        }
      }

      let techniqueId = rawId && validTechniqueIds.has(rawId) ? rawId : null;
      if (!techniqueId) {
        // Bonus recovery, not a requirement: if the model got the real
        // technique name right but botched/omitted the ID, an exact
        // (case-insensitive) name match against the real catalog is safe to
        // backfill -- it's not a guess, it's looking up a name the model
        // already committed to.
        techniqueId = techniqueNameToId.get(techniqueName.toLowerCase()) ?? null;
      }
      return {
        technique: techniqueName,
        techniqueId,
        reason: safeString(v.reason),
        killChainPhase: safeString(v.killChainPhase),
      };
    });
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

function parseModelReport(text, validTechniqueIds, techniqueNameToId, idToTechniqueName) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    const parsed = JSON.parse(text.slice(start, end + 1));
    if (!parsed || typeof parsed !== "object") return null;
    return {
      aiTechnicalSummary: safeAiTechnicalSummary(parsed.aiTechnicalSummary, validTechniqueIds, idToTechniqueName),
      executiveSummary: safeString(parsed.executiveSummary),
      businessImpact: safeBusinessImpact(parsed.businessImpact),
      threatOverview: safeThreatOverview(parsed.threatOverview, validTechniqueIds, idToTechniqueName),
      affectedProducts: safeAffectedProducts(parsed.affectedProducts),
      vendorSeverityAssessment: safeVendorSeverityAssessment(parsed.vendorSeverityAssessment),
      mitreAttack: safeMitreArray(parsed.mitreAttack, validTechniqueIds, techniqueNameToId, idToTechniqueName),
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
      threatIntelTakeaway: safeString(parsed.threatIntelTakeaway),
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

const TECHNIQUE_CANDIDATE_LIMIT = 30;

// Keyword-overlap scoring against this app's own synced MITRE ATT&CK catalog
// (server/connectors/attack.js), same weighted-keyword-match philosophy as
// server/githubIntel/classifier.js -- not a semantic match, just enough to
// hand the model a short, plausible, real-ID candidate list instead of
// letting it free-associate from ~600 techniques' worth of training memory.
function selectCandidateTechniques(article, techniques) {
  const words = new Set(`${article.title} ${article.summary ?? ""}`.toLowerCase().match(/[a-z0-9]{4,}/g) ?? []);
  if (words.size === 0) return [];
  const scored = [];
  for (const t of techniques) {
    const nameWords = t.name.toLowerCase().match(/[a-z0-9]{4,}/g) ?? [];
    const score = nameWords.filter((w) => words.has(w)).length;
    if (score > 0) scored.push({ t, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, TECHNIQUE_CANDIDATE_LIMIT).map((s) => s.t);
}

function buildTechniqueCandidatesBlock(candidates) {
  if (candidates.length === 0) {
    return "CANDIDATE MITRE ATT&CK TECHNIQUES: none pre-matched this article's keywords. Set techniqueId to null for every entry unless you are certain of a real, well-known technique ID -- never invent one.";
  }
  const lines = candidates.map((t) => `${t.id} -- ${t.name} (${t.tactic})`).join("\n");
  return `CANDIDATE MITRE ATT&CK TECHNIQUES (techniqueId must be copied exactly from this list, or null if none genuinely apply):\n${lines}`;
}

// Grounds the Sigma/YARA hunting-query fields the same way the rest of this
// module grounds CVEs/IOCs/MITRE IDs: cross-references the model's own named
// malware families/threat actors (not the model's invented rule content)
// against server/connectors/detectionRules.js's real, synced index of ~4000
// SigmaHQ/Yara-Rules community rules, via the exact same substring-match
// helper server/correlate.js already uses elsewhere in this app. Only Sigma
// and YARA get this treatment -- Sentinel/Defender KQL, Splunk SPL, Elastic,
// CrowdStrike, and Carbon Black have no equivalent free bulk rule catalog
// synced anywhere in this app, so there's nothing real to ground those
// against; they stay the model's own synthesis. Real hits are appended
// (not swapped in), so a model-drafted query for the same platform isn't lost.
const MAX_DETECTION_RULE_HITS_PER_PLATFORM = 8;

function groundHuntingRules(modelReport, ruleIndex) {
  if (!ruleIndex?.length) return modelReport;

  const names = [...modelReport.malware.map((m) => m.family), ...modelReport.threatActors.map((a) => a.group)].filter((n) => n && n !== "Not Reported");

  const seen = new Set();
  const sigmaHits = [];
  const yaraHits = [];
  for (const name of names) {
    for (const hit of detectionRulesFor(name, ruleIndex)) {
      const key = `${hit.label}:${hit.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const line = `${hit.label} (public, existing rule): ${hit.path} -- ${hit.url}`;
      if (hit.label === "SigmaHQ") sigmaHits.push(line);
      else if (hit.label === "YARA-Rules") yaraHits.push(line);
    }
  }
  if (sigmaHits.length === 0 && yaraHits.length === 0) return modelReport;

  return {
    ...modelReport,
    threatHuntingOpportunities: {
      ...modelReport.threatHuntingOpportunities,
      sigma: [...modelReport.threatHuntingOpportunities.sigma, ...sigmaHits].slice(0, MAX_DETECTION_RULE_HITS_PER_PLATFORM),
      yara: [...modelReport.threatHuntingOpportunities.yara, ...yaraHits].slice(0, MAX_DETECTION_RULE_HITS_PER_PLATFORM),
    },
  };
}

/**
 * @param {object} article - {title, summary, link, source, publishedDate}
 * @param {object} grounded - already-verified per-article facts from server/newsCorrelation.js#tagNewsItems
 * @param {string[]} grounded.cveIds
 * @param {string} grounded.severity - uppercase Severity ("CRITICAL"/"HIGH"/"MEDIUM"/"LOW")
 * @param {object} grounded.cveEnrichment - cveId -> {severity, cvssScore, knownExploited, epssScore, sourceUrl}
 * @param {Array} grounded.attackTechniques - this app's synced MITRE ATT&CK technique catalog, {id, name, tactic}[]
 * @param {Array} grounded.detectionRuleIndex - server/connectors/detectionRules.js's synced SigmaHQ/YARA-Rules filename-word index
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

  const techniques = grounded.attackTechniques ?? [];
  const candidateTechniques = selectCandidateTechniques(article, techniques);
  const validTechniqueIds = new Set(techniques.map((t) => t.id));
  const techniqueNameToId = new Map(techniques.map((t) => [t.name.toLowerCase(), t.id]));
  const idToTechniqueName = new Map(techniques.map((t) => [t.id, t.name]));

  const userContent =
    `Source: ${article.source}\nHeadline: ${article.title}\n` +
    (article.summary ? `Summary: ${article.summary}\n` : "") +
    (cveContext ? `Verified CVE data for this article (use this, don't restate or contradict it): ${cveContext}\n` : "") +
    `Overall severity already computed for this article: ${grounded.severity}\n` +
    `${buildTechniqueCandidatesBlock(candidateTechniques)}\n`;

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

  const modelReport = parseModelReport(response.message?.content ?? "", validTechniqueIds, techniqueNameToId, idToTechniqueName);
  if (!modelReport) return null;

  const groundedReport = groundHuntingRules(modelReport, grounded.detectionRuleIndex);

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
    ...groundedReport,
  };
}
