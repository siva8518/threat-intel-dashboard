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

// Reads EVERY matched entity (not just [0] -- that was only ever a display
// precedence, see evidence.js's own fix), aggregated into one impact/scope/
// technical-severity read.
function nameEntitySeverityFactors(moduleData) {
  const malware = (moduleData?.malware ?? []).map((m) => m.entity ?? m);
  const actors = moduleData?.actors ?? [];
  const campaigns = moduleData?.campaigns ?? [];
  if (malware.length === 0 && actors.length === 0 && campaigns.length === 0) return notApplicableFactors("No matched malware/actor/campaign entity.");

  const primaryActor = actors.find((a) => a.type === "Ransomware" || a.type === "APT") ?? actors[0];
  const totalSightings = malware.reduce((sum, m) => sum + (m.iocSightings ?? 0), 0);
  const kind = malware.length > 0 ? "malware family" : primaryActor ? "threat actor" : "campaign";

  const potentialImpact =
    primaryActor && (primaryActor.type === "Ransomware" || primaryActor.type === "APT")
      ? `${primaryActor.type} actor -- historically capable of severe operational/data impact.${actors.length > 1 ? ` (${actors.length} matched actor record(s) total.)` : ""}`
      : totalSightings > 0
        ? `${malware.length} matched malware famil${malware.length === 1 ? "y" : "ies"} with ${totalSightings} live indicator sighting(s) total -- actively observed in the wild.`
        : `Tracked ${kind}(s) (${malware.length} malware, ${actors.length} actor, ${campaigns.length} campaign record(s) matched), no elevated impact signal beyond being tracked.`;
  const industries = new Set([...actors.flatMap((a) => a.targetedIndustries ?? []), ...campaigns.flatMap((c) => c.targetedIndustries ?? [])]);
  const countries = new Set([...actors.flatMap((a) => a.targetedCountries ?? []), ...campaigns.flatMap((c) => c.targetedCountries ?? [])]);
  const scope = industries.size > 0 || countries.size > 0
    ? `Targeted industries: ${Array.from(industries).slice(0, 5).join(", ") || "not specified"}; countries: ${Array.from(countries).slice(0, 5).join(", ") || "not specified"}.`
    : "Scope not separately tracked for this entity type.";
  const techniqueCount = new Set(actors.flatMap((a) => a.techniqueIds ?? [])).size;
  const technicalSeverity =
    totalSightings > 0
      ? `${totalSightings} live indicator sighting(s) tracked across ${malware.length} malware famil${malware.length === 1 ? "y" : "ies"}.`
      : techniqueCount > 0
        ? `${techniqueCount} distinct tracked ATT&CK technique(s) used across ${actors.length} matched actor(s).`
        : "No technical detail tracked for campaigns beyond associated actors/malware.";

  return {
    potentialImpact,
    scope,
    technicalSeverity,
    businessContext: NO_BUSINESS_CONTEXT,
    reasoning: `Derived from this platform's own ${malware.length + actors.length + campaigns.length} matched entity record(s), independent of how many external sources corroborate their existence.`,
  };
}

// Reads the full dossier (entityCorrelation.js), not victimCount alone --
// a real verified actor/malware/campaign profile is itself an impact
// signal, distinct from (and additive to) raw disclosed-victim count.
function ransomwareGroupSeverityFactors(moduleData) {
  const count = moduleData?.victimCount ?? 0;
  const dossier = moduleData?.dossier;
  const hasProfile = dossier?.sourceType === "verified-profile";

  return {
    potentialImpact:
      count > 0
        ? `Ransomware group with ${count} disclosed victim(s) -- historically capable of full operational disruption and data extortion.${hasProfile ? ` Also matched a verified profile in this platform's own entity stores (${dossier.malwareFamilyCount} malware famil(ies), ${dossier.campaignCount} campaign(s)).` : ""}`
        : hasProfile
          ? `No disclosed victims tracked, but matched a verified malware/actor/campaign profile (${dossier.malwareFamilyCount} malware famil(ies), ${dossier.campaignCount} campaign(s), ${dossier.cveCount} CVE(s)) -- real correlation exists beyond the bare group-name classification.`
          : "No disclosed victims and no matched entity profile -- potential impact based on the ransomware-tracker group classification alone.",
    scope: count > 0 ? `${count} distinct victim organization(s) disclosed.` : "No victim-disclosure scope data available in this platform's data.",
    technicalSeverity: "Ransomware groups by nature deploy encryption/extortion payloads -- inherently high technical severity whenever active.",
    businessContext: NO_BUSINESS_CONTEXT,
    reasoning: `${count} disclosed victim(s) and dossier.sourceType="${dossier?.sourceType ?? "unverified-mention"}" together drive potentialImpact/scope; technicalSeverity reflects the ransomware-group classification itself, independent of either.`,
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
  if (entityType === "ransomwareGroup") {
    // Graded on the full dossier (entityCorrelation.js), not victimCount
    // alone -- the literal fix for the reported "Clop is CRITICAL purely
    // because it has victims, nothing else considered" bug. A recognized
    // ransomware-tracker group name is never silently UNKNOWN, even with
    // zero disclosed victims and no matched entity profile -- it's still
    // meaningfully "a real, named group," just weaker signal than a
    // corroborated one.
    const count = context.moduleData?.victimCount ?? 0;
    const dossier = context.moduleData?.dossier;
    const hasProfile = dossier?.sourceType === "verified-profile";
    if (count >= 10 && hasProfile) return "CRITICAL";
    if (count > 0 || (hasProfile && (dossier.malwareFamilyCount > 0 || dossier.campaignCount > 0))) return "HIGH";
    return "MEDIUM";
  }
  if (entityType === "name") {
    // Reads every matched entity, not just [0] -- `[0]` was only ever a
    // display precedence (entityCorrelation.js#pickPrimaryEntity), never
    // meant to make severity blind to every OTHER real match.
    const malware = (context.moduleData?.malware ?? []).map((m) => m.entity ?? m);
    const actors = context.moduleData?.actors ?? [];
    const campaigns = context.moduleData?.campaigns ?? [];
    const primaryActor = actors.find((a) => a.type === "Ransomware" || a.type === "APT") ?? actors[0];
    const totalSightings = malware.reduce((sum, m) => sum + (m.iocSightings ?? 0), 0);
    if (primaryActor && (primaryActor.type === "Ransomware" || primaryActor.type === "APT")) return "HIGH";
    if (totalSightings > 0) return "HIGH";
    if (malware.length > 0 || actors.length > 0 || campaigns.length > 0) return "MEDIUM";
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

// Computed once and shared between computeVerdictState and
// buildAnalystDecisionReasoning below so the reasoning text can never
// describe a different evidence pattern than the one that actually decided
// the state -- this is the fix for the reported "AI says multiple
// independent, corroborated sources confirm malicious activity" bug, which
// traced to a STATIC reasoning string keyed only by decision name, shown
// regardless of whether one source or several actually agreed.
/** Exported for reuse by shouldICare.js/correlationSummary.js's own AI-prose grounding pass (see groundClaims.js#checkMultiSourceCorroborationClaim) -- same signal breakdown that decides the verdict, never recomputed a second way. */
export function evidenceSignals(evidence) {
  const bearing = evidenceBearingItems(evidence);
  const directMalicious = bearing.filter((i) => i.category === "direct" && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const corroboratingMalicious = bearing.filter((i) => i.category === "corroborating" && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const indirectOrAttributionMalicious = bearing.filter((i) => (i.category === "indirect" || i.category === "attribution") && (i.polarity === "malicious" || i.polarity === "suspicious"));
  const negativeOnly = bearing.length > 0 && bearing.every((i) => i.category === "negative" || i.polarity === "benign");
  const allNeutral = bearing.length > 0 && bearing.every((i) => i.polarity === "neutral");
  const strongSingle = bearing.some((i) => i.weight >= 0.85);
  const strongestDirect = directMalicious.reduce((max, i) => (i.weight > (max?.weight ?? -1) ? i : max), null);
  const independentDirectSourceNames = Array.from(new Set(directMalicious.map((i) => i.source)));
  const noFindingSourceNames = (evidence.cards ?? []).filter((c) => c.level === "UNKNOWN").map((c) => c.source);

  return {
    bearing,
    directMalicious,
    corroboratingMalicious,
    indirectOrAttributionMalicious,
    negativeOnly,
    allNeutral,
    strongSingle,
    strongestDirect,
    independentDirectSourceNames,
    independentDirectSources: independentDirectSourceNames.length,
    noFindingSourceNames,
  };
}

function computeVerdictState(entityType, evidence, cveExploitationState, signals) {
  if (evidence.hasConflict) return "Conflicting Intelligence";
  if (entityType === "cve") return CVE_STATE_MAP[cveExploitationState?.state] ?? "Insufficient Evidence";

  const { bearing, directMalicious, corroboratingMalicious, indirectOrAttributionMalicious, negativeOnly, allNeutral, strongSingle, independentDirectSources } = signals;

  if ((strongSingle && directMalicious.length > 0) || independentDirectSources >= 2) return "Confirmed Malicious";
  if (directMalicious.length >= 1 || corroboratingMalicious.length >= 2) return "Malicious";
  if (corroboratingMalicious.length >= 1 || indirectOrAttributionMalicious.length >= 1) return "Suspicious";
  if (negativeOnly) return "Clean-Benign";
  if (allNeutral) return "Informational"; // e.g. a verified/tracked entity found, but with no currently-active malicious signal
  if (bearing.length === 0) return "Insufficient Evidence";
  return "Unconfirmed";
}

// The literal "top of page should NOT primarily say 'X is malicious'" fix --
// leads with the real correlation counts the dossier (entityCorrelation.js)
// assembled, e.g. "Clop is an active ransomware/extortion group with 3
// campaigns, 1 malware family, 7 CVEs, 146 IOCs, 20 disclosed victims, 4
// related threat reports in this platform," falling back to the old bare
// victim-count framing only when the dossier found nothing beyond the raw
// tracker match.
function buildLabel(entityType, state, cveExploitationState, context) {
  if (entityType === "cve" && cveExploitationState) return cveExploitationState.label;
  if (entityType === "ransomwareGroup") {
    const md = context.moduleData;
    const count = md?.victimCount ?? 0;
    const d = md?.dossier;
    if (!d || (count === 0 && d.sourceType !== "verified-profile")) {
      return count > 0 ? `Active Ransomware Group — ${count} Disclosed Victim(s)` : "No Disclosed Victims Found in This Platform's Data";
    }
    const parts = [];
    if (d.campaignCount > 0) parts.push(`${d.campaignCount} campaign${d.campaignCount === 1 ? "" : "s"}`);
    if (d.malwareFamilyCount > 0) parts.push(`${d.malwareFamilyCount} malware famil${d.malwareFamilyCount === 1 ? "y" : "ies"}`);
    if (d.cveCount > 0) parts.push(`${d.cveCount} CVE${d.cveCount === 1 ? "" : "s"}`);
    if (d.iocCount > 0) parts.push(`${d.iocCount} IOC${d.iocCount === 1 ? "" : "s"}`);
    if (count > 0) parts.push(`${count} disclosed victim${count === 1 ? "" : "s"}`);
    if (d.threatReportCount > 0) parts.push(`${d.threatReportCount} related threat report${d.threatReportCount === 1 ? "" : "s"}`);
    return parts.length > 0
      ? `Active ransomware/extortion group with ${parts.join(", ")} in this platform`
      : "Recognized Ransomware Group — Limited Correlation Found in This Platform's Data";
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
/** Exported for reuse by server/investigation/actionability.js's environmentalValidationPlan(), which needs the same blockable/non-blockable split when phrasing its recommended next actions. */
export const BLOCKABLE_TYPES = new Set(["ip", "domain", "url", "sha256", "sha1", "md5"]);

// Real ASN-holder/warning-list phrasing this platform's own connectors
// already produce for major cloud/CDN/VPN/datacenter providers (see
// evidence.js's ripestatRule/teamCymruAsnRule/mispRule) -- reused here, not
// re-invented, to detect "this sits on shared infrastructure" without
// treating ownership itself as evidence (evidence.js already guarantees
// these items are always "contextual" or "negative" polarity, never
// malicious/suspicious).
const SHARED_INFRASTRUCTURE_PATTERN = /cloudflare|amazon|aws|azure|microsoft corporation|google cloud|gcp|oracle|digitalocean|akamai|fastly|ovh|hetzner|linode|vultr|\bvpn\b|datacenter|data center/i;

/** Exported for reuse by server/investigation/shouldICare.js, which surfaces this same signal to the analyst as an explicit "shared infrastructure" note. */
export function hasSharedInfrastructureSignal(evidence) {
  return evidence.items.some((i) => (i.category === "contextual" || i.category === "negative") && SHARED_INFRASTRUCTURE_PATTERN.test(i.claim));
}

// Real attribution -- a matched malware family or a named threat actor/
// campaign, not bare reputation. Deliberately does NOT include "indirect"
// items (algorithmic text-match inferences).
/** Exported for reuse by server/investigation/shouldICare.js. */
export function hasKnownAttribution(evidence) {
  return evidence.items.some((i) => i.category === "attribution" || i.rawField === "matchedMalwareFamilies");
}

function namedSources(names) {
  if (names.length === 0) return "no source";
  if (names.length === 1) return names[0];
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
}

/**
 * The literal fix for the reported "AI says multiple independent,
 * corroborated sources confirm malicious activity" hallucination -- this
 * used to be a STATIC string per decision name (e.g. every "Block" verdict
 * showed the same "Multiple independent, corroborated sources..." sentence
 * regardless of whether one source or several actually agreed). Every
 * sentence below is built from the real, already-computed evidenceSignals()
 * breakdown -- it can name exactly which source(s) provided the signal, and
 * explicitly says "X is the only source" when that's what happened, never
 * "multiple sources" unless independentDirectSources is actually >= 2.
 */
function buildAnalystDecisionReasoning(state, decision, evidence, signals) {
  const { independentDirectSourceNames, independentDirectSources, strongestDirect, corroboratingMalicious, indirectOrAttributionMalicious, noFindingSourceNames } = signals;
  const sharedInfra = hasSharedInfrastructureSignal(evidence);
  const attributed = hasKnownAttribution(evidence);
  const noFindingNote = noFindingSourceNames.length > 0 ? ` ${namedSources(noFindingSourceNames)} returned no notable finding.` : "";

  if (decision === "Block" || decision === "Investigate Immediately") {
    let base;
    if (independentDirectSources >= 2) {
      base = `${independentDirectSources} independent sources (${independentDirectSourceNames.join(", ")}) directly confirm malicious activity.`;
    } else if (independentDirectSources === 1 && strongestDirect) {
      base = `${strongestDirect.source} is the only source currently providing a malicious signal: ${strongestDirect.claim}.`;
    } else if (corroboratingMalicious.length > 0) {
      base = `${corroboratingMalicious.length} corroborating (not first-party direct) source(s) support this read: ${namedSources([...new Set(corroboratingMalicious.map((i) => i.source))])}.`;
    } else {
      base = "The available evidence supports this state.";
    }
    const attributionNote = attributed ? " A real attribution (malware family/actor/campaign) exists, which is why this is actionable regardless of any shared-infrastructure context." : "";
    return `${base}${noFindingNote}${attributionNote}`;
  }
  if (decision === "Investigate If Observed Internally") {
    if (evidence.hasConflict) return evidence.conflictDescription;
    if (sharedInfra && !attributed) return `This indicator sits on shared/cloud/VPN infrastructure with no confirmed malware/actor/campaign attribution -- reputation signal alone is not strong enough to block without more context.${noFindingNote}`;
    const names = Array.from(new Set([...corroboratingMalicious, ...indirectOrAttributionMalicious].map((i) => i.source)));
    if (names.length > 0) return `${namedSources(names)} provide${names.length === 1 ? "s" : ""} a suspicious, not yet strongly-corroborated signal.${noFindingNote}`;
    return `Evidence is suspicious or conflicting -- not strong enough alone to act on directly.${noFindingNote}`;
  }
  if (decision === "Monitor") return `No source provided a strong or corroborated malicious signal.${noFindingNote} Monitor for additional signal before acting.`;
  if (decision === "Watchlist") return "This is a tracked entity in this platform's data, but no source currently reports an active malicious signal for it -- keep on a watchlist, not an immediate action.";
  if (decision === "Do Not Block") {
    if (state === "Clean-Benign") {
      const names = Array.from(new Set(evidence.items.filter((i) => i.category === "negative").map((i) => i.source)));
      if (names.length > 0) return `${namedSources(names)} report${names.length === 1 ? "s" : ""} an explicit clean/benign signal, and no source reports malicious/suspicious activity.`;
    }
    return "No sufficient malicious evidence in this platform's current data to justify action.";
  }
  return `No evidence-bearing source was found or configured for this indicator.${noFindingNote}`; // No Action Required / Insufficient Evidence
}

/**
 * The type-agnostic analyst action -- computed from verdict state plus two
 * moderating signals read directly from the evidence: shared/cloud/VPN
 * infrastructure context, and whether there's a real attribution (not bare
 * reputation). A strong reputation-only verdict on shared infrastructure
 * with no attribution caps at "Investigate If Observed Internally" instead
 * of "Block" -- a real attribution overrides that caution even on shared
 * hosting (e.g. a VirusTotal-confirmed C2 for a known malware family still
 * reads "Block" regardless of which cloud it's hosted on).
 */
function computeAnalystDecision(entityType, state, evidence) {
  const blockable = BLOCKABLE_TYPES.has(entityType);
  if (state === "Confirmed Malicious" || state === "Malicious") {
    if (!blockable) return "Investigate Immediately";
    const sharedInfra = hasSharedInfrastructureSignal(evidence);
    const attributed = hasKnownAttribution(evidence);
    if (sharedInfra && !attributed) return "Investigate If Observed Internally";
    return state === "Confirmed Malicious" ? "Block" : "Investigate Immediately";
  }
  if (state === "Suspicious" || state === "Conflicting Intelligence") return "Investigate If Observed Internally";
  if (state === "Unconfirmed") return "Monitor";
  if (state === "Informational") return "Watchlist";
  if (state === "Clean-Benign") return "Do Not Block";
  return "No Action Required"; // Insufficient Evidence
}

const ANALYST_DECISION_TO_BLOCK = {
  Block: "Block",
  "Investigate Immediately": "Monitor — Do Not Block",
  "Investigate If Observed Internally": "Monitor — Do Not Block",
  Monitor: "Monitor — Do Not Block",
  Watchlist: "Do Not Block",
  "Do Not Block": "Do Not Block",
  "No Action Required": "Do Not Block",
};

/** Derived from analystDecision (never independently recomputed), so the two can't disagree -- "Not Applicable" for entity types blocking doesn't apply to. */
function computeBlockRecommendation(entityType, analystDecision, analystDecisionReasoning) {
  if (!BLOCKABLE_TYPES.has(entityType)) {
    return { blockRecommendation: "Not Applicable", blockRecommendationReasoning: `Blocking is not a meaningful action for a "${entityType}" entity.` };
  }
  return { blockRecommendation: ANALYST_DECISION_TO_BLOCK[analystDecision] ?? "Do Not Block", blockRecommendationReasoning: analystDecisionReasoning };
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
  const signals = evidenceSignals(evidence);
  const state = computeVerdictState(entityType, evidence, cveExploitationState, signals);
  const severityFactors = computeSeverityFactors(entityType, evidence, cveExploitationState, context);
  const severity = computeSeverityLevel(entityType, evidence, context);
  const label = buildLabel(entityType, state, cveExploitationState, context);
  const reasoning = buildReasoning(state, evidence, cveExploitationState);
  const analystDecision = computeAnalystDecision(entityType, state, evidence);
  const analystDecisionReasoning = buildAnalystDecisionReasoning(state, analystDecision, evidence, signals);
  const { blockRecommendation, blockRecommendationReasoning } = computeBlockRecommendation(entityType, analystDecision, analystDecisionReasoning);

  return {
    state,
    label,
    confidence,
    confidenceFactors,
    severity,
    severityFactors,
    riskLevel: SEVERITY_TO_RISK[severity] ?? "Low",
    recommendedPriority: SEVERITY_TO_PRIORITY[severity] ?? "Low",
    analystDecision,
    analystDecisionReasoning,
    blockRecommendation,
    blockRecommendationReasoning,
    reasoning,
    evidence,
    conflicts: evidence.hasConflict ? [evidence.conflictDescription] : [],
  };
}
