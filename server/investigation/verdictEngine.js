// Unified verdict engine -- Stages 4-6 of the shared platform-wide
// intelligence assessment pipeline (Confidence -> Severity/Priority ->
// combined into one VerdictState), replacing server/investigation/verdict.js's
// four separate, type-specific functions that all routed through one
// `fromLevel(level)` bucket where severity/riskLevel/priority were three
// views of the same number and confidence was a hardcoded literal per
// branch. Here confidence and severity are computed by entirely separate
// factor lists and combined with the evidence pattern only at the very end,
// via one decision table every entity type shares -- this file is what
// makes the framework platform-wide rather than per-type.
const SEVERITY_TO_RISK = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", UNKNOWN: "Low" };
const SEVERITY_TO_PRIORITY = { CRITICAL: "Immediate", HIGH: "High", MEDIUM: "Normal", LOW: "Low", UNKNOWN: "Low" };

// CVE exploitation state -> verdict state. Deliberately NOT the same
// ordering as the old KEV > EPSS > CVSS chain -- EPSS alone (a prediction)
// can never reach Malicious/Confirmed Malicious, only Unconfirmed.
const CVE_STATE_MAP = {
  confirmed_actively_exploited: "Confirmed Malicious",
  exploitation_reported_unconfirmed: "Malicious",
  public_exploit_available: "Suspicious",
  poc_only: "Suspicious",
  predicted_high_risk_epss: "Unconfirmed",
  no_known_exploitation: "Informational",
};

const STATE_LABELS = {
  "Confirmed Malicious": "Malicious",
  Malicious: "Malicious",
  Suspicious: "Suspicious",
  "Conflicting Intelligence": "Conflicting Intelligence",
  Unconfirmed: "Unconfirmed",
  "Clean-Benign": "Clean",
  Informational: "Informational",
  "Insufficient Evidence": "No Data",
};

function evidenceBearingItems(evidence) {
  return evidence.items.filter((i) => i.category !== "contextual" && i.category !== "conflicting");
}

// --- Confidence -- how sure we are, purely from evidence quantity/
// independence/agreement/recency. Never reads severity inputs. ---

function computeConfidenceFactors(evidence) {
  const bearing = evidenceBearingItems(evidence);
  const corroborationCount = bearing.filter((i) => i.polarity === "malicious" || i.polarity === "suspicious").length;
  const timestamps = bearing
    .map((i) => i.lastSeen || i.firstSeen)
    .filter(Boolean)
    .map((d) => new Date(d).getTime())
    .filter((t) => !Number.isNaN(t));
  const recencyDays = timestamps.length > 0 ? Math.round((Date.now() - Math.max(...timestamps)) / 86_400_000) : null;

  const reasoning =
    evidence.sourceCount === 0
      ? "No evidence-bearing source was found or configured for this indicator."
      : `${evidence.sourceCount} evidence item(s) from ${evidence.independentSourceCount} independent source(s), ${corroborationCount} agreeing on a malicious/suspicious read${recencyDays != null ? `, most recent ${recencyDays} day(s) ago` : ""}.`;

  return { sourceCount: evidence.sourceCount, independentSourceCount: evidence.independentSourceCount, corroborationCount, recencyDays, reasoning };
}

function deriveConfidenceLevel(factors, evidence) {
  if (evidence.hasConflict) return "Low"; // disagreeing sources make the TRUTH less certain, regardless of any one source's own strength
  const bearing = evidenceBearingItems(evidence);
  const hasStrongSingleSource = bearing.some((i) => i.weight >= 0.8);
  if (factors.independentSourceCount >= 2 && factors.corroborationCount >= 2) return "High";
  if (hasStrongSingleSource && factors.independentSourceCount >= 1) return "High";
  if (factors.independentSourceCount >= 1 && factors.corroborationCount >= 1) return "Medium";
  if (factors.sourceCount > 0) return "Medium";
  return "Low";
}

// --- Severity -- how bad it would be if true, from entity-type-specific
// impact factors. Never reads confidence inputs; for CVEs, never reads
// cveExploitationState either (a CVSS 9.8 CVE with no known exploitation
// still reports HIGH technical severity -- exploitation likelihood is a
// separate, independently-tracked concept). ---

function notApplicableFactors(reasoning) {
  return { potentialImpact: "Not Applicable", scope: "Not Applicable", technicalSeverity: "Not Applicable", businessContext: "Not Applicable", reasoning };
}

const NO_BUSINESS_CONTEXT = "Not Applicable -- this platform has no asset/business-context integration to assess impact against a specific organization's environment.";

function iocSeverityFactors(evidence, context) {
  const bearing = evidenceBearingItems(evidence);
  const strongest = bearing.reduce((max, i) => (i.weight > (max?.weight ?? -1) ? i : max), null);
  const malwareFamilies = context.crossRef?.matchedMalwareFamilies ?? [];
  const siblingCount = context.crossRef?.siblingIndicators?.length ?? 0;

  return {
    potentialImpact:
      malwareFamilies.length > 0
        ? `Linked to tracked malware famil${malwareFamilies.length === 1 ? "y" : "ies"} (${malwareFamilies.join(", ")}) -- impact scoped to that family's known capabilities.`
        : "No specific malware family attribution -- impact assessed from raw indicator behavior alone.",
    scope: siblingCount > 0 ? `Part of a cluster of ${siblingCount} related indicator(s) already tracked by this platform, not an isolated sighting.` : "No other related indicators found in this platform's own tracked intelligence -- appears to be an isolated sighting.",
    technicalSeverity: strongest ? `Strongest single signal: ${strongest.source} -- ${strongest.claim}.` : "No source reported a meaningful reputation signal for this indicator.",
    businessContext: NO_BUSINESS_CONTEXT,
    reasoning: `Severity derived independently of confidence: ${malwareFamilies.length > 0 ? "known malware association" : "no malware association"}, ${siblingCount > 0 ? "part of a tracked cluster" : "isolated sighting"}, strongest raw signal from ${strongest ? strongest.source : "none"}.`,
  };
}

function cveSeverityFactors(cve, exploitState) {
  if (!cve) return notApplicableFactors("No CVE record available.");
  return {
    potentialImpact: `CVSS ${cve.severity}${cve.cvssScore ? ` (${cve.cvssScore})` : ""} technical impact if exploited.`,
    scope: cve.vendor && cve.product ? `Affects ${cve.vendor} ${cve.product} -- scope limited to environments running this product.` : "Affected product/vendor not precisely identified in this platform's data.",
    technicalSeverity: `CVSS severity: ${cve.severity}${cve.cvssScore ? ` (base score ${cve.cvssScore})` : ""} -- independent of whether exploitation has actually been observed.`,
    businessContext: NO_BUSINESS_CONTEXT,
    reasoning: `Severity reflects CVSS technical impact alone; exploitation likelihood is tracked separately as its own exploitation state (currently: ${exploitState?.label ?? "unknown"}).`,
  };
}

function nameEntitySeverityFactors(moduleData) {
  const malware = moduleData?.malware?.[0]?.entity;
  const actor = moduleData?.actors?.[0];
  const campaign = moduleData?.campaigns?.[0];
  if (!malware && !actor && !campaign) return notApplicableFactors("No matched malware/actor/campaign entity.");

  const kind = malware ? "malware family" : actor ? "threat actor" : "campaign";
  const potentialImpact =
    actor && (actor.type === "Ransomware" || actor.type === "APT")
      ? `${actor.type} actor -- historically capable of severe operational/data impact.`
      : malware && (malware.iocSightings ?? 0) > 0
        ? `Malware family with ${malware.iocSightings} live indicator sighting(s) -- actively observed in the wild.`
        : `Tracked ${kind}, no elevated impact signal beyond being tracked.`;
  const scope = actor
    ? `Targeted industries: ${(actor.targetedIndustries ?? []).slice(0, 5).join(", ") || "not specified"}; countries: ${(actor.targetedCountries ?? []).slice(0, 5).join(", ") || "not specified"}.`
    : campaign
      ? `Targeted industries: ${(campaign.targetedIndustries ?? []).slice(0, 5).join(", ") || "not specified"}.`
      : "Scope not separately tracked for this entity type.";
  const technicalSeverity = malware
    ? `${malware.iocSightings ?? 0} live indicator sighting(s) tracked.`
    : actor
      ? `${(actor.techniqueIds ?? []).length} tracked ATT&CK technique(s) used.`
      : "No technical detail tracked for campaigns beyond associated actors/malware.";

  return { potentialImpact, scope, technicalSeverity, businessContext: NO_BUSINESS_CONTEXT, reasoning: `Derived from this platform's own ${kind} record, independent of how many external sources corroborate its existence.` };
}

function ransomwareGroupSeverityFactors(moduleData) {
  const count = moduleData?.victimCount ?? 0;
  return {
    potentialImpact: count > 0 ? `Ransomware group with ${count} disclosed victim(s) -- historically capable of full operational disruption and data extortion.` : "No disclosed victims tracked -- potential impact based on ransomware-group classification alone.",
    scope: count > 0 ? `${count} distinct victim organization(s) disclosed.` : "No victim-disclosure scope data available in this platform's data.",
    technicalSeverity: "Ransomware groups by nature deploy encryption/extortion payloads -- inherently high technical severity whenever active.",
    businessContext: NO_BUSINESS_CONTEXT,
    reasoning: `${count} disclosed victim(s) drives potentialImpact/scope; technicalSeverity reflects the ransomware-group classification itself, independent of victim count.`,
  };
}

function genericSeverityFactors(entityType, evidence) {
  const hasEvidence = evidenceBearingItems(evidence).length > 0;
  return {
    potentialImpact: hasEvidence ? "Linked to this platform's own tracked malicious activity -- see evidence." : "No malicious association found in this platform's own tracked intelligence.",
    scope: "Not independently trackable for this entity type beyond what the evidence above shows.",
    technicalSeverity: hasEvidence ? "Reflects this platform's own cross-referenced intelligence only -- no dedicated external reputation source exists for this indicator type." : "No technical severity signal available.",
    businessContext: NO_BUSINESS_CONTEXT,
    reasoning: `"${entityType}" has no dedicated external reputation source; severity is derived solely from this platform's own cross-referenced intelligence.`,
  };
}

function computeSeverityFactors(entityType, evidence, cveExploitationState, context) {
  if (entityType === "cve") return cveSeverityFactors(context.moduleData?.cve, cveExploitationState);
  if (entityType === "name") return nameEntitySeverityFactors(context.moduleData);
  if (entityType === "ransomwareGroup") return ransomwareGroupSeverityFactors(context.moduleData);
  if (["ip", "domain", "url", "sha256", "sha1", "md5"].includes(entityType)) return iocSeverityFactors(evidence, context);
  return genericSeverityFactors(entityType, evidence);
}

function computeSeverityLevel(entityType, evidence, context) {
  if (entityType === "cve") return context.moduleData?.cve?.severity ?? "UNKNOWN";
  if (entityType === "ransomwareGroup") return (context.moduleData?.victimCount ?? 0) > 0 ? "CRITICAL" : "UNKNOWN";
  if (entityType === "name") {
    const malware = context.moduleData?.malware?.[0]?.entity;
    const actor = context.moduleData?.actors?.[0];
    const campaign = context.moduleData?.campaigns?.[0];
    if (actor && (actor.type === "Ransomware" || actor.type === "APT")) return "HIGH";
    if (malware && (malware.iocSightings ?? 0) > 0) return "HIGH";
    if (malware || actor || campaign) return "MEDIUM";
    return "UNKNOWN";
  }
  // Deliberately NOT driven by evidence weight/agreement (that's what
  // confidence is for -- see requirement "Severity != Confidence"). A
  // single weak, unattributed, even CONFLICTING signal still means "we
  // don't know the potential impact", which is MEDIUM by default, not LOW
  // (LOW would wrongly imply a known-small impact) and not tied to how
  // many sources happen to agree. Severity only rises above that baseline
  // when there's a specific impact driver (attribution to a known malware
  // family, multiple independent direct confirmations, or one very strong
  // direct signal), and only drops to LOW when the evidence is exclusively
  // negative/clean, or UNKNOWN when there's no evidence at all.
  const bearing = evidenceBearingItems(evidence);
  if (bearing.length === 0) return "UNKNOWN";
  const maliciousLike = bearing.filter((i) => i.polarity === "malicious" || i.polarity === "suspicious");
  if (maliciousLike.length === 0) return "LOW"; // only negative/clean/neutral evidence found
  const malwareFamilies = context.crossRef?.matchedMalwareFamilies ?? [];
  const maxWeight = bearing.reduce((max, i) => Math.max(max, i.weight), 0);
  const independentDirectMaliciousSources = new Set(maliciousLike.filter((i) => i.category === "direct").map((i) => i.source)).size;
  if (malwareFamilies.length > 0 && independentDirectMaliciousSources >= 1) return "CRITICAL"; // attributed to a known malware family with direct confirmation
  if (independentDirectMaliciousSources >= 2 || maxWeight >= 0.8) return "HIGH"; // strong or multiply-confirmed malicious signal, even without family attribution
  return "MEDIUM"; // a malicious/suspicious signal exists but isn't yet strongly corroborated -- uncharacterized potential impact, never downgraded to LOW just because the evidence is weak or conflicting
}

// --- Verdict state -- the one decision table every entity type shares.
// Conflicting evidence always wins first, regardless of individual item
// strength; CVEs route through their own exploitation-state mapping (never
// vote-counted); every other entity type shares the same evidence-pattern
// ladder below. ---

function computeVerdictState(entityType, evidence, cveExploitationState, context) {
  if (evidence.hasConflict) return "Conflicting Intelligence";
  if (entityType === "cve") return CVE_STATE_MAP[cveExploitationState?.state] ?? "Insufficient Evidence";

  const bearing = evidenceBearingItems(evidence);
  const directMalicious = bearing.filter((i) => i.category === "direct" && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const corroboratingMalicious = bearing.filter((i) => i.category === "corroborating" && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const indirectOrAttributionMalicious = bearing.filter((i) => (i.category === "indirect" || i.category === "attribution") && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const negativeOnly = bearing.length > 0 && bearing.every((i) => i.category === "negative" || i.polarity === "benign");
  const allNeutral = bearing.length > 0 && bearing.every((i) => i.polarity === "neutral");
  const strongSingle = bearing.some((i) => i.weight >= 0.85);
  const independentDirectSources = new Set(directMalicious.map((i) => i.source)).size;

  if ((strongSingle && directMalicious.length > 0) || independentDirectSources >= 2) return "Confirmed Malicious";
  if (directMalicious.length >= 1 || corroboratingMalicious.length >= 2) return "Malicious";
  if (corroboratingMalicious.length >= 1 || indirectOrAttributionMalicious.length >= 1) return "Suspicious";
  if (negativeOnly) return "Clean-Benign";
  if (allNeutral) return "Informational"; // e.g. a verified/tracked entity found, but with no currently-active malicious signal
  if (bearing.length === 0) return "Insufficient Evidence";
  return "Unconfirmed";
}

function buildLabel(entityType, state, cveExploitationState, context) {
  if (entityType === "cve" && cveExploitationState) return cveExploitationState.label;
  if (entityType === "ransomwareGroup") {
    const count = context.moduleData?.victimCount ?? 0;
    return count > 0 ? `Active Ransomware Group — ${count} Disclosed Victim(s)` : "No Disclosed Victims Found in This Platform's Data";
  }
  return STATE_LABELS[state] ?? state;
}

function buildReasoning(state, evidence, cveExploitationState) {
  if (evidence.hasConflict) return evidence.conflictDescription;
  if (cveExploitationState) return cveExploitationState.reasoning;
  const bearing = evidenceBearingItems(evidence);
  if (bearing.length === 0) return "No evidence-bearing source was found or configured for this indicator.";
  const named = bearing.slice(0, 3).map((i) => i.source);
  return `${state} based on ${bearing.length} evidence item(s) from ${evidence.independentSourceCount} independent source(s): ${named.join(", ")}${bearing.length > 3 ? ", …" : ""}.`;
}

// Blocking is only ever a meaningful action for network/file IOCs -- never
// for a CVE (you patch it, you don't "block" a vulnerability), an actor/
// malware/campaign name, a ransomware group, or any of the other entity
// types this framework covers.
const BLOCKABLE_TYPES = new Set(["ip", "domain", "url", "sha256", "sha1", "md5"]);

/**
 * Deterministic, evidence-derived block/don't-block call -- a fifth output
 * alongside state/severity/confidence/priority, computed from the verdict
 * STATE alone (never from severity or raw evidence weight directly), so weak
 * or conflicting reputation data can never produce "Block" no matter how
 * elevated severity happens to be (e.g. Conflicting Intelligence always
 * routes to "Monitor -- Do Not Block", even when severity reads HIGH).
 */
function computeBlockRecommendation(entityType, state) {
  if (!BLOCKABLE_TYPES.has(entityType)) {
    return { blockRecommendation: "Not Applicable", blockRecommendationReasoning: `Blocking is not a meaningful action for a "${entityType}" entity.` };
  }
  if (state === "Confirmed Malicious") {
    return { blockRecommendation: "Block", blockRecommendationReasoning: "Multiple independent, corroborating sources (or one very strong, high-confidence source) confirm malicious activity." };
  }
  if (state === "Malicious") {
    return { blockRecommendation: "Block", blockRecommendationReasoning: "Direct evidence of malicious activity from at least one reliable source, with no conflicting negative evidence." };
  }
  if (state === "Suspicious") {
    return { blockRecommendation: "Monitor — Do Not Block", blockRecommendationReasoning: "Evidence suggests risk but is not strong or corroborated enough alone to justify blocking." };
  }
  if (state === "Conflicting Intelligence") {
    return { blockRecommendation: "Monitor — Do Not Block", blockRecommendationReasoning: "Sources disagree -- do not block based on current, conflicting threat-intelligence evidence." };
  }
  return { blockRecommendation: "Do Not Block", blockRecommendationReasoning: "No sufficient malicious evidence in this platform's current data to justify blocking." };
}

/**
 * Confidence + Severity/Priority + final verdict state -- the one function
 * every entity type routes through.
 *
 * @param {{ entityType: string, evidence: import("../../src/types/threat-intel.js").EvidenceReconciliation, cveExploitationState?: import("../../src/types/threat-intel.js").CveExploitationAssessment | null, context?: { moduleData?: Record<string, unknown>, crossRef?: Record<string, unknown> | null, graph?: unknown } }} args
 * @returns {import("../../src/types/threat-intel.js").VerdictResult}
 */
export function computeVerdict({ entityType, evidence, cveExploitationState = null, context = {} }) {
  const confidenceFactors = computeConfidenceFactors(evidence);
  const confidence = deriveConfidenceLevel(confidenceFactors, evidence);
  const state = computeVerdictState(entityType, evidence, cveExploitationState, context);
  const severityFactors = computeSeverityFactors(entityType, evidence, cveExploitationState, context);
  const severity = computeSeverityLevel(entityType, evidence, context);
  const label = buildLabel(entityType, state, cveExploitationState, context);
  const reasoning = buildReasoning(state, evidence, cveExploitationState);
  const { blockRecommendation, blockRecommendationReasoning } = computeBlockRecommendation(entityType, state);

  return {
    state,
    label,
    confidence,
    confidenceFactors,
    severity,
    severityFactors,
    riskLevel: SEVERITY_TO_RISK[severity] ?? "Low",
    recommendedPriority: SEVERITY_TO_PRIORITY[severity] ?? "Low",
    blockRecommendation,
    blockRecommendationReasoning,
    reasoning,
    evidence,
    conflicts: evidence.hasConflict ? [evidence.conflictDescription] : [],
  };
}
