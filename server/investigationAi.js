// On-demand AI Investigation Report for the Investigation Workspace --
// "Generate AI Report" button only (never fired automatically on search).
//
// Redesigned per user requirement: behave like a senior Threat Intelligence
// Analyst, not a generic summarizer. The core discipline is separating what
// this platform's OWN deterministic engines already established (never
// re-derived or re-guessed by the model) from what the model is genuinely
// being asked to synthesize -- and never letting the model's synthesis
// overstate what the evidence supports.
//
// Three kinds of content in the final report:
//   1. DETERMINISTIC, pulled straight from this platform's existing engines,
//      never touched by the model: verdict/severity/confidence
//      (verdictEngine.js), confirmedFacts (evidence.js's own claim strings --
//      already real, numeric, source-attributed), sourceIntelligence (built
//      here directly from the raw per-source lookup results, so a source
//      that returned nothing is reported as exactly that, never invented),
//      ATT&CK mapping (server/investigation/index.js's mitreMappingFor, real
//      evidence-backed techniques), related campaigns/actors/malware
//      (crossReference.js), and the block/containment recommendation
//      (verdictEngine.js#computeBlockRecommendation, already tested against
//      7 required scenarios).
//   2. MODEL-AUTHORED SYNTHESIS, grounded and validated after the fact:
//      executive assessment, assessed conclusions (each with its own
//      evidence-derived confidence), potential attack role, correlation
//      assessment, intelligence gaps, next pivot, and the three role-specific
//      action lists.
//   3. Evidence-gated guards (server/investigation/groundClaims.js) applied
//      to every model-authored field -- particularly the NEW
//      checkAttackChainStageClaim, which is the direct fix for the reported
//      "concludes initial access from a bare malicious hash" problem: a
//      specific attack-chain stage (initial access, persistence, lateral
//      movement, credential theft, exfiltration, encryption, ransomware
//      deployment, C2) may only be asserted when real behavioral evidence
//      (a sandbox execution report, or this platform's own real ATT&CK
//      mapping) actually exists for this indicator -- never from a
//      multi-engine malicious verdict alone.
import { aiRouter } from "./ai/aiRouter.js";
import { AI_TASK } from "./ai/aiTasks.js";
import { hashForCacheKey } from "./ai/aiResponseCache.js";
import { evidenceSignals, hasKnownAttribution } from "./investigation/verdictEngine.js";
import {
  checkProseGrounding,
  checkCveExploitationClaim,
  checkAttackChainStageClaim,
  checkUnsupportedClaims,
  checkInternalTelemetryClaim,
  checkIocAttributionClaim,
} from "./investigation/groundClaims.js";

const CONFIDENCE_LEVELS = new Set(["High", "Medium", "Low", "Unknown"]);

function safeString(value, fallback = "Not established by available evidence.") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}
function safeArray(value, max = 10) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string" && v.trim()).slice(0, max) : [];
}
function safeConfidence(value) {
  return CONFIDENCE_LEVELS.has(value) ? value : "Unknown";
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
 * Every configured source's contribution, itemized -- built entirely in
 * code from the raw per-source result objects (never model-authored, so a
 * source can never be silently dropped or have a field invented). A source
 * that returned no usable fields is reported as "no_data" rather than
 * omitted; a source that wasn't configured or was skipped/rate-limited is
 * still listed with that exact status.
 */
function buildSourceIntelligence(moduleData) {
  if (!moduleData || moduleData.noExternalSource) return [];
  const results = Array.isArray(moduleData.lookupResults) ? moduleData.lookupResults : [];
  const notConfigured = moduleData.notConfigured ?? [];
  const skipped = moduleData.skipped ?? [];
  const rateLimited = moduleData.rateLimited ?? [];

  const items = [];
  for (const r of results) {
    if (!r || typeof r !== "object") continue;
    const { source, verdict, ...rest } = r;
    const fields = Object.entries(rest)
      .filter(([, v]) => v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0) && !(typeof v === "string" && v.trim() === ""))
      .map(([key, value]) => ({ key, value: Array.isArray(value) ? value.slice(0, 10) : value }));
    items.push({
      source: source ?? "Unknown source",
      status: fields.length > 0 || (verdict && verdict !== "unknown") ? "data_returned" : "no_data",
      verdict: verdict ?? null,
      fields,
    });
  }
  for (const s of notConfigured) items.push({ source: s, status: "not_configured", verdict: null, fields: [] });
  for (const s of rateLimited) items.push({ source: s, status: "rate_limited", verdict: null, fields: [] });
  for (const s of skipped) items.push({ source: s.source ?? String(s), status: "skipped", verdict: null, fields: s.reason ? [{ key: "reason", value: s.reason }] : [] });
  return items;
}

/** Real, code-generated fact strings (evidence.js's own `claim` field -- already numeric and source-attributed, e.g. "58 engine(s) flagged malicious (trojan.direwolf/schoolboy)") -- this is what "Observed Intelligence" renders, never a model restatement. */
function buildConfirmedFacts(evidence) {
  return evidenceBearingClaims(evidence).map((i) => ({ source: i.source, fact: i.claim }));
}

function evidenceBearingClaims(evidence) {
  return (evidence?.items ?? []).filter((i) => i.category !== "negative" || i.polarity !== "neutral");
}

/** True only when real behavioral evidence exists for this indicator -- a sandbox execution report, or this platform's own real, evidence-backed ATT&CK technique mapping. A bare multi-engine malicious verdict is explicitly NOT behavioral evidence. */
function hasBehavioralEvidence(moduleData, mitreAttackMapping) {
  if ((mitreAttackMapping ?? []).length > 0) return true;
  const behavior = moduleData?.behavior;
  if (behavior?.available) return true;
  return false;
}

/**
 * Deterministic, code-generated hunting query for THIS search's own real
 * indicator value -- never model-authored, so the field/table names and the
 * IOC value itself are always exactly right (the direct fix for asking the
 * model to invent correct-looking-but-unverifiable KQL syntax). Modeled on
 * Microsoft Defender Advanced Hunting schema, the same convention this
 * platform's other hunting-query content (server/huntingLibrary.js) already
 * targets. Returns null for indicator types with no applicable query
 * template (cve/name/ransomwareGroup/email/etc.) rather than fabricating one.
 */
function buildDetectionQuery(type, indicator) {
  if (type === "sha256" || type === "sha1" || type === "md5") {
    const field = { sha256: "SHA256", sha1: "SHA1", md5: "MD5" }[type];
    return {
      platform: "Microsoft Defender for Endpoint",
      language: "KQL",
      query:
        `DeviceFileEvents\n` +
        `| where ${field} == "${indicator}"\n` +
        `| project\n` +
        `    Timestamp,\n` +
        `    DeviceName,\n` +
        `    ActionType,\n` +
        `    FileName,\n` +
        `    FolderPath,\n` +
        `    SHA256,\n` +
        `    SHA1,\n` +
        `    MD5,\n` +
        `    InitiatingProcessFileName,\n` +
        `    InitiatingProcessCommandLine,\n` +
        `    InitiatingProcessAccountName\n` +
        `| order by Timestamp desc`,
    };
  }
  if (type === "ip") {
    return {
      platform: "Microsoft Defender for Endpoint",
      language: "KQL",
      query:
        `DeviceNetworkEvents\n` +
        `| where RemoteIP == "${indicator}"\n` +
        `| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName\n` +
        `| order by Timestamp desc`,
    };
  }
  if (type === "domain") {
    return {
      platform: "Microsoft Defender for Endpoint",
      language: "KQL",
      query:
        `DeviceNetworkEvents\n` +
        `| where RemoteUrl has "${indicator}"\n` +
        `| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName\n` +
        `| order by Timestamp desc`,
    };
  }
  if (type === "url") {
    return {
      platform: "Microsoft Defender for Endpoint",
      language: "KQL",
      query:
        `DeviceNetworkEvents\n` +
        `| where RemoteUrl == "${indicator}"\n` +
        `| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName\n` +
        `| order by Timestamp desc`,
    };
  }
  return null;
}

// Generic, non-actionable conclusion language this platform never emits as
// a standalone recommendation -- the direct fix for the reported "Monitor" /
// "Suspicious" / "Requires Investigation" / "treat this as context" filler
// items with no concrete data source, IOC, or escalation path attached. A
// match means the model produced a vague conclusion instead of an
// executable action; that item is dropped rather than shown half-formed.
const GENERIC_ACTION_PATTERN =
  /^(monitor( the environment)?|investigate further|requires? investigation|suspicious|be cautious|exercise caution|treat this as context|the final (soc )?decision should)\.?$/i;

function isActionableItem(text) {
  return typeof text === "string" && text.trim().length > 20 && !GENERIC_ACTION_PATTERN.test(text.trim());
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
  if (moduleData.noExternalSource) return { noExternalSource: true, note: moduleData.note };
  return {
    relatedIndicators: moduleData.relatedIndicators
      ? {
          sameCampaignOrActorCount: moduleData.relatedIndicators.sameCampaignOrActor?.length ?? 0,
          sameCampaignOrActorFamilies: [...new Set((moduleData.relatedIndicators.sameCampaignOrActor ?? []).map((r) => r.malwareFamily))],
          sameAsnCount: moduleData.relatedIndicators.sameAsn?.length ?? 0,
        }
      : undefined,
  };
}

/**
 * @param {import("./investigation/index.js").InvestigationResult} investigation
 */
function buildContext(investigation) {
  const { indicator, type, overview, moduleData, relatedIntelligence } = investigation;
  const { verdict } = overview;
  const signals = evidenceSignals(verdict.evidence);
  const mitreAttackMapping = overview.mitreAttackMapping ?? [];

  return {
    indicator,
    type,
    verdictState: verdict.state,
    verdictLabel: verdict.label,
    severity: verdict.severity,
    riskLevel: verdict.riskLevel,
    confidence: verdict.confidence,
    confidenceReasoning: verdict.confidenceFactors.reasoning,
    severityReasoning: verdict.severityFactors.reasoning,
    blockRecommendation: verdict.blockRecommendation,
    conflicts: verdict.conflicts,
    // Real, code-computed evidence tallies (verdictEngine.js#evidenceSignals)
    // -- the same signals that decided the verdict, exposed here so the
    // model reasons over actual counts instead of a bare label, and so a
    // deterministic confidence row can be derived for the Confidence Table
    // without trusting the model to self-assess it.
    independentDirectSourceCount: signals.independentDirectSources,
    directMaliciousCount: signals.directMalicious.length,
    corroboratingMaliciousCount: signals.corroboratingMalicious.length,
    indirectOrAttributionCount: signals.indirectOrAttributionMalicious.length,
    strongestDirectClaim: signals.strongestDirect ? { source: signals.strongestDirect.source, claim: signals.strongestDirect.claim } : null,
    hasKnownAttribution: hasKnownAttribution(verdict.evidence),
    hasBehavioralEvidence: hasBehavioralEvidence(moduleData, mitreAttackMapping),
    cveExploitationState: overview.cveExploitationState ? { state: overview.cveExploitationState.state, label: overview.cveExploitationState.label, reasoning: overview.cveExploitationState.reasoning } : null,
    firstSeen: overview.firstSeen,
    lastSeen: overview.lastSeen,
    activeCampaigns: overview.activeCampaigns,
    associatedThreatActors: overview.associatedThreatActors,
    mitreAttackMapping,
    relatedIntelligence,
    moduleSummary: summarizeModuleData(type, moduleData),
    confirmedFacts: buildConfirmedFacts(verdict.evidence),
    sourceIntelligence: buildSourceIntelligence(moduleData),
    iocRecord: relatedIntelligence?.canonicalRecord ?? null,
    detectionQuery: buildDetectionQuery(type, indicator),
  };
}

const SYSTEM_PROMPT =
  "You are a senior Threat Intelligence Analyst investigating a single indicator for a fellow analyst. " +
  "You are given: the indicator and type; this platform's ALREADY-COMPUTED verdict, severity, and confidence (never re-derive these -- explain them, don't restate or contradict them); real, source-attributed confirmedFacts (already-verified evidence, cite these directly rather than re-describing the raw numbers yourself); a full sourceIntelligence breakdown per configured source (including sources that returned nothing); real evidence-count signals (independentDirectSourceCount, directMaliciousCount, corroboratingMaliciousCount, indirectOrAttributionCount, hasKnownAttribution, hasBehavioralEvidence); the real ATT&CK mapping this platform already computed (mitreAttackMapping); related campaigns/actors/malware this platform has already correlated; and, when applicable to this indicator type, a deterministic detectionQuery (platform/language/query) already built with this exact indicator value substituted in -- reference it in detectionEngineerActions rather than writing your own query syntax. " +
  "\n\nYOUR JOB is synthesis, not restatement: explain what the evidence collectively means, where sources agree or conflict, what can be reasonably assessed versus what remains genuinely unknown, and concrete next actions -- never invent a fact, entity, or relationship not present in what you were given.\n" +
  "\n\nCRITICAL ANTI-HALLUCINATION RULES (a programmatic check runs after your response, so follow these exactly):\n" +
  "1. Never invent a threat actor, campaign, malware family, or C2 infrastructure not already named in activeCampaigns/associatedThreatActors/relatedIntelligence.\n" +
  "2. Shared ASN/hosting/infrastructure co-location is NEVER by itself evidence of attribution.\n" +
  '3. Never claim a specific attack-chain stage -- "initial access", "persistence", "lateral movement", "credential theft", "data exfiltration", "data encryption", "ransomware deployment", "C2 channel" -- unless hasBehavioralEvidence is true. If it is false, describe this only as a "potential role in the attack chain" with the exact position explicitly stated as not established.\n' +
  "4. Never claim active compromise, an active attack on an environment, or presence/absence in an environment -- this platform has no internal telemetry.\n" +
  "5. Never claim ransomware deployment or campaign membership solely from a ransomware-related tag or label -- only when confirmedFacts or sourceIntelligence directly supports it.\n" +
  '6. Never state a CVE is "actively exploited"/"confirmed exploited" unless cveExploitationState is confirmed_actively_exploited or exploitation_reported_unconfirmed.\n' +
  "7. Never convert a source tag/label into a confirmed behavioral fact -- a ransomware-family label means the sample is associated with that family's tooling, not that ransomware was deployed in an intrusion.\n" +
  '8. Every assessedConclusions entry must state an honest confidence: "High" only when independentDirectSourceCount >= 2 or hasKnownAttribution is true for that specific claim; "Medium" for a single strong direct source or corroborating pattern; "Low" for indirect/weak signal only; "Unknown" when the claim genuinely cannot be assessed from what you were given.\n' +
  '9. Every recommendation in threatIntelActions/detectionEngineerActions/socInvestigationActions/securityEngineeringActions must follow this exact structure in one or two sentences: Action -> Data/Telemetry source -> the SPECIFIC IOC/TTP value from this context -> Expected result/what a hit or miss means -> Escalation/next step. Example: "Search the SHA256 <indicator> across DeviceFileEvents and process-execution telemetry. If observed on any endpoint, identify execution status, parent process, user, and command line. If execution occurred, correlate the host against related domains/IPs from this report and escalate for endpoint containment." Never a bare instruction like "check system logs" or "review OTX pulses" with no specifics, and never a standalone conclusion word with nothing executable attached (\"Monitor\", \"Suspicious\", \"Requires Investigation\", \"treat this as context\" are NOT actions -- a programmatic filter strips any item matching that shape, so write past it).\n' +
  "10. Internal-tool actions (EDR/SIEM/firewall/DNS/proxy/email/web-gateway) must be phrased as conditional recommendations for the analyst's OWN tools (\"if observed in your EDR...\"), never as something this platform itself checked.\n" +
  '11. containmentRationale must explain the ALREADY-COMPUTED blockRecommendation you were given -- never propose a different containment action or invent urgency the evidence does not support.\n' +
  '12. Never create a standalone "Assessment" or "Key Intelligence Note" section, and never reconcile a conflicting reputation/sandbox verdict into a generic risk statement (e.g. "Hybrid Analysis reports a conflicting clean/benign signal, treat this as context"). If sources conflict, name the conflict AND its resolution path directly inside the relevant team\'s action item (per rule 9\'s structure) instead.\n' +
  "13. detectionEngineerActions is mandatory whenever the indicator itself is a usable IOC (hash/IP/domain/URL) -- it must explicitly reference the exact indicator value and, if a detectionQuery was provided in your context, tell the analyst to run/validate it; if none was provided, explain exactly what detection/hunting alternative applies instead (e.g. behavioral/Sigma coverage for a malware family, not a raw IOC match).\n" +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"indicatorVerdictExplanation": string -- 1-2 sentences explaining WHY this indicator earned its given verdict/severity, citing specific confirmedFacts/sourceIntelligence -- do not restate the verdict label itself.\n' +
  '"executiveAssessment": string -- 2-4 sentences, the single most important synthesis of what this indicator represents and why it matters, grounded only in provided data.\n' +
  '"assessedConclusions": array of 3-6 {"claim": string, "confidence": "High"|"Medium"|"Low"|"Unknown", "reasoning": string} -- reasonable conclusions derived FROM the evidence (not bare facts, not wild speculation), each with an honest, evidence-derived confidence per rule 8 above.\n' +
  '"potentialAttackRole": string -- what role this indicator may play in an attack chain. Per rule 3: only name a specific stage if hasBehavioralEvidence is true; otherwise write it as an explicitly unresolved "potential role", e.g. "may represent a payload or later-stage component; its exact position in the attack chain is not established by the available intelligence."\n' +
  '"correlationAssessment": string -- 2-4 sentences on how the sources corroborate or conflict: what multiple sources independently agree on, what only one source contributes, and what remains uncorroborated. Per rule 12, if sources conflict, state the conflict plainly here as analysis (this field is narrative, not an action list) -- do not invent a separate assessment label for it.\n' +
  '"intelligenceGaps": string[] -- 2-6 specific things this platform\'s current intelligence does NOT establish about this indicator (e.g. "no evidence confirming execution in a customer environment", "no confirmed C2 infrastructure for this specific sample"). Never fill a gap with an assumption -- name it as a gap instead.\n' +
  '"recommendedNextPivot": string -- the SINGLE highest-value next investigation step, specific to this indicator (name the actual value/field to pivot on).\n' +
  '"threatIntelActions": string[] -- 3-6 items, per rule 9. Cover: validating the IOC across the sourceIntelligence sources given; related infrastructure/hashes/domains/IPs/filenames/certificates; whether this is part of an existing campaign; attribution if hasKnownAttribution supports it; affected industries if known; whether the threat is active or historical (firstSeen/lastSeen); updating this platform\'s own watchlist/intelligence records.\n' +
  '"detectionEngineerActions": string[] -- 3-6 items, per rules 9-10 and mandatory per rule 13. Cover: the concrete detection/hunting query for this exact indicator (reference the provided detectionQuery when present); which EDR/SIEM/telemetry sources to search; what the detection should surface (host, first/last seen, filename/process/user/command-line/network activity, quarantine status where applicable); and whether this indicator should be added to an EDR blocklist, SIEM rule, TI watchlist, or SOAR workflow (only when blockRecommendation actually supports it -- do not default to "add to blocklist").\n' +
  '"socInvestigationActions": string[] -- 3-6 items, per rules 9-10. Cover: what to investigate (host/user/process/network), what telemetry/log sources to check, parent/child process relationships, whether to search this exact IOC across the environment, what related domains/IPs/processes/files/users to also investigate, what evidence to collect, and the specific condition that would trigger escalation. Do not recommend containment here; that is containmentRationale below.\n' +
  '"securityEngineeringActions": string[] -- 3-6 items, per rules 9-10. Preventive/control-layer actions tied to THIS indicator/TTP specifically (EDR prevention/blocking, email security, web proxy, DNS controls, firewall rules, application control, endpoint hardening) -- never generic security-hygiene advice disconnected from this indicator.\n' +
  '"containmentRationale": string -- explains the given blockRecommendation per rule 11. If blockRecommendation is "Not Applicable" or "Do Not Block", say so plainly rather than inventing a containment need.\n' +
  "No other text, no markdown formatting, no code fences.";

/**
 * @param {import("./investigation/index.js").InvestigationResult} investigation
 */
export async function generateInvestigationAiReport(investigation) {
  const context = buildContext(investigation);
  const userPrompt = `INDICATOR CONTEXT (verified by this platform, not model-generated):\n${JSON.stringify(context, null, 2)}\n\nProduce the JSON report described in your instructions for this indicator.`;

  const result = await aiRouter.summarizeJson(userPrompt, {
    systemPrompt: SYSTEM_PROMPT,
    temperature: 0.3,
    task: AI_TASK.INVESTIGATION,
    cacheKey: `investigation-ai-report:${hashForCacheKey(context)}`,
  });
  const parsed = parseModelReport(result.summary);
  if (!parsed) throw new Error("AI Investigation Report: model response was not valid JSON");

  const allowedNames = [context.indicator, ...(context.activeCampaigns ?? []), ...(context.associatedThreatActors ?? []), ...(context.relatedIntelligence?.matchedMalwareFamilies ?? [])];
  const groundingContext = { hasAttribution: context.hasKnownAttribution, hasEnvironmentalTelemetry: false };

  // Raw text of this search's own deterministic source data (VirusTotal
  // threatLabel, OTX pulse names/tags, etc.) -- already surfaced verbatim in
  // the sourceIntelligence section of this same report, so a name found
  // here isn't the model inventing a relationship, it's citing evidence the
  // user can already see. Exempts those from checkProseGrounding's caveat
  // (see that function's own comment for why this was needed).
  const sourceCitedText = JSON.stringify(context.sourceIntelligence ?? []) + JSON.stringify(context.confirmedFacts ?? []);

  // Full grounding pipeline -- every model-authored prose field goes through
  // the same ordered chain: real-entity grounding -> CVE-exploitation gate ->
  // attack-chain-stage gate -> the small set of especially consequential
  // absolute-claim rules (C2/attribution/ransomware-membership/environment)
  // -> IOC-attribution cross-check where an indicator-level record exists.
  function ground(text) {
    let t = checkProseGrounding(text, allowedNames, sourceCitedText).text;
    t = checkCveExploitationClaim(t, context.cveExploitationState).text;
    t = checkAttackChainStageClaim(t, context.hasBehavioralEvidence).text;
    t = checkUnsupportedClaims(t, groundingContext).text;
    if (context.iocRecord) t = checkIocAttributionClaim(t, context.iocRecord).text;
    return t;
  }
  function groundAction(text) {
    return checkInternalTelemetryClaim(ground(text)).text;
  }
  // Grounds every item in an action list, then drops any that are still just
  // a generic, non-executable conclusion (see GENERIC_ACTION_PATTERN) even
  // after grounding -- per rule 9/12, this platform never surfaces a bare
  // "Monitor"/"Suspicious"/"Requires Investigation" line as a recommendation.
  function groundActionList(items, max) {
    return safeArray(items, max).map(groundAction).filter(isActionableItem);
  }

  const assessedConclusions = (Array.isArray(parsed.assessedConclusions) ? parsed.assessedConclusions : []).slice(0, 6).map((c) => ({
    claim: ground(safeString(c?.claim)),
    confidence: safeConfidence(c?.confidence),
    reasoning: safeString(c?.reasoning, ""),
  }));

  // Deterministic headline confidence row -- computed directly from the real
  // evidence-count signals, never left to the model to self-assess. Merged
  // in front of the model's own assessedConclusions rows.
  const maliciousConfidence =
    context.independentDirectSourceCount >= 2 ? "High" : context.directMaliciousCount >= 1 ? "Medium" : context.corroboratingMaliciousCount >= 1 || context.indirectOrAttributionCount >= 1 ? "Low" : "Unknown";
  const confidenceTable = [
    {
      claim: "Indicator is malicious/suspicious",
      confidence: maliciousConfidence,
      reasoning: `Derived from ${context.independentDirectSourceCount} independent direct source(s), ${context.directMaliciousCount} direct malicious signal(s), ${context.corroboratingMaliciousCount} corroborating signal(s).`,
    },
    ...assessedConclusions.map((c) => ({ claim: c.claim, confidence: c.confidence, reasoning: c.reasoning })),
  ];

  // Real, un-invented gaps -- every not-configured/skipped/rate-limited
  // source from the deterministic sourceIntelligence breakdown becomes its
  // own gap entry, merged with the model's own genuinely-assessed gaps.
  const sourceGaps = context.sourceIntelligence.filter((s) => s.status !== "data_returned" && s.status !== "no_data").map((s) => `${s.source}: ${s.status.replace("_", " ")} -- no intelligence available from this source.`);

  return {
    indicator: context.indicator,
    verdictLabel: context.verdictLabel,
    verdictState: context.verdictState,
    severity: context.severity,
    confidence: context.confidence,
    indicatorVerdictExplanation: ground(safeString(parsed.indicatorVerdictExplanation)),
    executiveAssessment: ground(safeString(parsed.executiveAssessment)),
    confirmedFacts: context.confirmedFacts,
    sourceIntelligence: context.sourceIntelligence,
    assessedConclusions,
    potentialAttackRole: ground(safeString(parsed.potentialAttackRole)),
    correlationAssessment: ground(safeString(parsed.correlationAssessment)),
    mitreAttackMapping: context.mitreAttackMapping,
    relatedIntelligence: {
      activeCampaigns: context.activeCampaigns,
      associatedThreatActors: context.associatedThreatActors,
      matchedMalwareFamilies: context.relatedIntelligence?.matchedMalwareFamilies ?? [],
    },
    confidenceTable,
    intelligenceGaps: [...safeArray(parsed.intelligenceGaps, 6), ...sourceGaps].slice(0, 10),
    recommendedNextPivot: ground(safeString(parsed.recommendedNextPivot)),
    threatIntelActions: groundActionList(parsed.threatIntelActions, 6),
    detectionEngineerActions: groundActionList(parsed.detectionEngineerActions, 6),
    socInvestigationActions: groundActionList(parsed.socInvestigationActions, 6),
    securityEngineeringActions: groundActionList(parsed.securityEngineeringActions, 6),
    detectionQuery: context.detectionQuery,
    blockRecommendation: context.blockRecommendation,
    containmentRationale: ground(safeString(parsed.containmentRationale)),
    model: result.model,
    provider: result.provider,
    generatedAt: new Date().toISOString(),
  };
}
