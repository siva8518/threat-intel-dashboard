// Programmatic AI-claim validation -- generalizes server/industryBriefing.js's
// groundedArticles() (validates every model-cited article INDEX against a
// real pool, silently discarding invented ones) into a NAME-based validator
// for the Investigation Workspace's AI layers (graphInsights.js,
// correlationSummary.js, investigationAi.js), which ask the model to name
// entities in free-text/JSON fields rather than cite pool indices.
//
// Until this file, every one of those three layers' "never invent a
// relationship/actor/exploitation claim" rules was prompt-only -- trust the
// model, no code that actually checks a named entity appears in the real
// data it was handed. This is the first code-enforced layer: structured
// name fields (strongestActorMatch, priorityInvestigationTargets) are
// stripped/dropped outright when ungrounded; free-text prose fields get a
// best-effort cross-check against this platform's own entity stores (can't
// fully parse prose for entity mentions, but CAN detect when the model
// names a REAL platform-tracked actor/malware/campaign that has nothing to
// do with THIS search -- the concrete, checkable version of "don't invent
// attribution") and get a visible caveat appended rather than being
// silently trusted or silently discarded.
import { getAllEntities as getActorEntities } from "../threatActorIntelligence.js";
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getCampaignEntities } from "../campaignIntelligence.js";

export const NOT_ESTABLISHED = "Not established by available evidence.";

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

function isGrounded(name, allowedNames) {
  const n = norm(name);
  if (!n) return false;
  return allowedNames.some((a) => {
    const an = norm(a);
    return an && (an === n || an.includes(n) || n.includes(an));
  });
}

/** Validates a single free-text name field (e.g. strongestActorMatch.name) -- returns it unchanged if grounded, `null` otherwise so the caller can drop the whole nullable object rather than keep a fabricated name. */
export function groundName(name, allowedNames) {
  return isGrounded(name, allowedNames) ? name : null;
}

/** Validates a list of {entity, ...} objects (e.g. priorityInvestigationTargets) -- DROPS any entry whose entity name isn't grounded, rather than replacing it: a missing recommendation is safer than a fabricated one still occupying a "you should investigate this" slot. */
export function groundEntityList(list, allowedNames, entityKey = "entity") {
  if (!Array.isArray(list)) return [];
  return list.filter((item) => item && typeof item === "object" && isGrounded(item[entityKey], allowedNames));
}

// Confirmed live: this app's news-extraction pipeline leaves genuinely
// junk/placeholder records in these stores -- e.g. a malware entity
// literally named "malware" (verified:true but zero real signal: 0
// iocSightings, 0 articles) and an unverified single-mention actor entity
// literally named "CISA" (a government agency, not a threat actor,
// mis-extracted from an article headline). Cross-checking prose against
// those would flag completely ordinary words as "unverified attribution."
// `verified` alone isn't enough (the junk "malware" record is verified),
// so real signal (mentionCount/iocSightings/articles) is required too.
function hasRealSignal(entity) {
  return Boolean(entity.verified) && ((entity.mentionCount ?? 0) > 0 || (entity.iocSightings ?? 0) > 0 || (entity.articles ?? []).length > 0);
}

/** Every actor/malware/campaign name this platform genuinely tracks with real signal -- used only to detect the specific, checkable hallucination pattern of the model naming a REAL platform entity that has nothing to do with THIS search (not a fully-fabricated name, which no code can verify against ground truth). Recomputed each call -- these are cheap in-memory array reads, not I/O, and the stores are updated periodically by background extraction jobs while the server runs. */
function allKnownEntityNames() {
  return [...getActorEntities().filter(hasRealSignal).map((e) => e.name), ...getMalwareEntities().filter(hasRealSignal).map((e) => e.name), ...getCampaignEntities().filter(hasRealSignal).map((e) => e.name)].filter(Boolean);
}

/**
 * Best-effort prose grounding check -- flags (never silently discards) a
 * narrative field that mentions a real, platform-tracked actor/malware/
 * campaign name NOT in this search's own `allowedNames`. Appends a visible
 * caveat rather than trusting the prose or dropping the whole paragraph
 * over one unverifiable name.
 */
export function checkProseGrounding(text, allowedNames) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  const allowedSet = new Set(allowedNames.map(norm));
  const lower = text.toLowerCase();
  const suspects = allKnownEntityNames().filter((name) => {
    const n = norm(name);
    if (n.length < 4 || allowedSet.has(n)) return false;
    return lower.includes(n);
  });
  if (suspects.length === 0) return { text, flagged: false };
  return {
    text: `${text} [Caveat: this platform could not verify the mention of ${suspects.slice(0, 3).join(", ")} against this search's own evidence -- treat as unconfirmed.]`,
    flagged: true,
  };
}

const CONFIRMED_EXPLOITATION_LANGUAGE = /actively exploited|confirmed exploit|being exploited in the wild|observed exploitation|exploitation has been confirmed/i;

/**
 * Blocks a narrative field from asserting confirmed active exploitation
 * language for a CVE unless this platform's own cveExploitationState
 * (server/investigation/cveExploitState.js) actually supports it --
 * directly enforces "never equate CVSS/EPSS/PoC-availability with confirmed
 * exploitation" at the AI-narrative layer, not just at verdict computation.
 */
export function checkCveExploitationClaim(text, cveExploitationState) {
  if (!text || typeof text !== "string" || !cveExploitationState) return { text, flagged: false };
  if (cveExploitationState.state === "confirmed_actively_exploited" || cveExploitationState.state === "exploitation_reported_unconfirmed") return { text, flagged: false };
  if (!CONFIRMED_EXPLOITATION_LANGUAGE.test(text)) return { text, flagged: false };
  return {
    text: `${text} [Caveat: this platform's own evidence does not confirm active exploitation for this CVE -- current exploitation state is "${cveExploitationState.label}".]`,
    flagged: true,
  };
}

// Each rule pairs a claim pattern with the specific boolean in
// `groundingContext` that must be true before that claim is allowed to
// stand -- a direct, one-to-one code enforcement of this platform's
// explicit "the AI MUST NOT say X unless Y" rules (server/investigation/
// shouldICare.js's SYSTEM_PROMPT states the same rules in the prompt too,
// but this is the part that actually can't be talked around by the model).
const UNSUPPORTED_CLAIM_RULES = [
  { pattern: /\bC2\b|command[- ]and[- ]control/i, requires: "hasAttribution", label: "command-and-control attribution" },
  { pattern: /belongs to (a |the )?(known |tracked )?threat actor|is (a |part of )?(a |the )?known threat actor/i, requires: "hasAttribution", label: "threat-actor ownership" },
  { pattern: /ransomware campaign|part of a ransomware/i, requires: "hasAttribution", label: "ransomware-campaign membership" },
  { pattern: /attacking your (organization|environment|network|company)|compromised your|has compromised your|is currently attacking|actively targeting your/i, requires: "hasEnvironmentalTelemetry", label: "a confirmed attack against your environment" },
  // Claiming ABSENCE ("not observed in our environment") is just as ungrounded
  // as claiming presence -- this platform has no telemetry to confirm either
  // direction, so a false "all clear" read is exactly as dangerous as a false
  // "you're compromised" read.
  { pattern: /not (currently |yet )?(been )?(observed|seen|detected|found|present)\s+in\s+(our|your|the)\s+(organization|environment|network)/i, requires: "hasEnvironmentalTelemetry", label: "knowledge of whether this indicator is present or absent in your environment" },
];

/**
 * Fail-closed version of the checks above -- for a small set of especially
 * consequential absolute claims (confirmed C2, threat-actor ownership,
 * ransomware-campaign membership, an active attack on YOUR environment),
 * an appended caveat isn't enough: the whole field is replaced with an
 * honest "not established" statement rather than left partially misleading.
 * `groundingContext` is real, code-computed evidence (see
 * server/investigation/verdictEngine.js#hasKnownAttribution and this
 * platform's environmental-telemetry status, currently always false --
 * see server/investigation/shouldICare.js), never taken from the model's
 * own output.
 */
export function checkUnsupportedClaims(text, groundingContext) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  for (const rule of UNSUPPORTED_CLAIM_RULES) {
    if (rule.pattern.test(text) && !groundingContext[rule.requires]) {
      return { text: `Not established by available evidence: this platform's data does not support a claim of ${rule.label}.`, flagged: true };
    }
  }
  return { text, flagged: false };
}

const MULTI_SOURCE_CORROBORATION_LANGUAGE = /\bmultiple\b[^.]{0,40}\b(source|sources|engines?|vendors?|feeds?)\b[^.]{0,40}\b(confirm|agree|corroborat|independent)|\b(several|numerous|many)\b[^.]{0,30}\bindependent\b[^.]{0,30}\bsources?\b|\bcorroborated by (multiple|several|numerous|many) (source|sources|vendors?)/i;

/**
 * Fail-closed guard for the specific, reported hallucination pattern this
 * platform's own verdict engine already fixed at the source (see
 * server/investigation/verdictEngine.js#buildAnalystDecisionReasoning's own
 * comment) -- kept here too as defense-in-depth for the AI-authored prose
 * layers (shouldICare.js/correlationSummary.js), which paraphrase the
 * verdict rather than quote it verbatim and could still independently claim
 * "multiple sources" on their own. `independentDirectMaliciousSourceCount`
 * is the real, code-computed count of independent DIRECT malicious/
 * suspicious sources (server/investigation/verdictEngine.js#evidenceSignals'
 * own tally) -- text claiming multi-source corroboration is only left
 * standing when that count is genuinely >= 2.
 */
export function checkMultiSourceCorroborationClaim(text, independentDirectMaliciousSourceCount) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  if (independentDirectMaliciousSourceCount >= 2 || !MULTI_SOURCE_CORROBORATION_LANGUAGE.test(text)) return { text, flagged: false };
  return {
    text: "Not established by available evidence: this platform's data does not support a claim of multi-source corroboration for this indicator -- at most one independent direct source currently provides a malicious/suspicious signal.",
    flagged: true,
  };
}

const INTERNAL_TELEMETRY_ACTION_LANGUAGE = /\b(search|check|query|identify|hunt (for|in)|correlate)\b[^.]{0,60}\b(EDR|SIEM|firewall|proxy logs?|DNS logs?|endpoint telemetry|network telemetry|email security logs?)\b/i;
const CONDITIONAL_QUALIFIER = /\bif\b[^.]{0,40}\b(observed|found|present|detected|seen|exists?|identified)\b/i;

/**
 * Defense-in-depth for this platform's explicit "never imply the platform
 * itself has EDR/SIEM/network-telemetry access" constraint. The primary fix
 * lives in the deterministic action strings (server/investigation/
 * actionability.js), which are never AI-authored -- this catches the same
 * pattern if AI-generated prose (shouldICare.js's nextAction, correlationSummary.js's
 * nextSteps) recommends an internal-tool search WITHOUT the required "if
 * observed in your X" conditional framing. Not a factual hallucination
 * (there's no boolean ground truth to check against), so this appends a
 * clarifying note rather than replacing the whole field -- the underlying
 * recommendation is still useful, it just needs the ownership boundary made
 * explicit.
 */
export function checkInternalTelemetryClaim(text) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  if (!INTERNAL_TELEMETRY_ACTION_LANGUAGE.test(text) || CONDITIONAL_QUALIFIER.test(text)) return { text, flagged: false };
  return {
    text: `${text} [Note: this platform has no EDR/SIEM/network-telemetry integration -- this is a recommendation for your own internal tools, not something this platform has already checked.]`,
    flagged: true,
  };
}

const SAFE_DEFAULT_INTENT_PHRASE = /not established|insufficient evidence|cannot (currently )?be determined/i;

/**
 * Fail-closed guard for the "Likely Malicious Intent" field -- the one
 * field this platform's redesigned evidence UI most needs to get right,
 * since a wrong or invented intent claim is the single most consequential
 * hallucination this platform can produce. `hasIntentEvidence` is a real,
 * code-computed boolean (see shouldICare.js -- true only when there's
 * genuine attribution or specific behavioral/malware-association evidence,
 * explicitly NEVER true from bare reputation scores/detection counts, ASN/
 * cloud/CDN ownership, domain-naming patterns, or multi-domain resolution
 * alone). If false, the whole field is replaced outright -- not caveated --
 * unless the model already wrote an honest "not established" statement
 * itself, in which case that's left as-is.
 */
export function checkMaliciousIntentClaim(text, hasIntentEvidence) {
  const fallback = "Not established from available intelligence -- insufficient evidence to determine intent.";
  if (!text || typeof text !== "string") return { text: fallback, flagged: true };
  if (hasIntentEvidence || SAFE_DEFAULT_INTENT_PHRASE.test(text)) return { text, flagged: false };
  return { text: fallback, flagged: true };
}

// The 3 entity-dossier-aware checks below (Phase 6 of the entity-centric
// correlation engine plan) follow the exact same fail-closed, whole-field-
// replacement shape as checkMaliciousIntentClaim above -- a caveat isn't
// enough for these because each pattern names a SPECIFIC relationship
// (this campaign, this CVE, this industry) that either is or isn't in the
// real dossier server/investigation/entityCorrelation.js#buildEntityDossier
// already computed. `has*` booleans are always real, code-computed values
// from that dossier (or `true`/no-op for indicator types that have no
// dossier at all, e.g. an IP/domain search) -- never taken from the model.

const CAMPAIGN_INVOLVEMENT_LANGUAGE = /\b(participated in|involved in|part of|conducted|carried out|orchestrated|the actor behind|responsible for)\b[^.]{0,60}\bcampaign\b/i;

/** Fail-closed guard for a claim that this entity took part in a specific campaign -- requires the dossier to actually have at least one campaign in its Campaign History; a bare 0-campaign dossier can never support this language, no matter how the model phrases it. */
export function checkCampaignInvolvementClaim(text, hasCampaignData) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  if (hasCampaignData || !CAMPAIGN_INVOLVEMENT_LANGUAGE.test(text)) return { text, flagged: false };
  return {
    text: "Not established by available evidence: this platform's dossier does not record a specific campaign association for this entity.",
    flagged: true,
  };
}

const CVE_EXPLOITATION_BY_ACTOR_LANGUAGE = /\b(exploit(s|ed|ing)?|leverage[sd]?|weaponiz(es|ed|ing)?|abuse[sd]?)\b[^.]{0,80}\bCVE-\d{4}-\d+/i;

/** Fail-closed guard for a claim that this entity exploits/exploited a named CVE -- requires the dossier to have at least one DIRECT (not INFERRED-via-actor) associatedCves entry (entityCorrelation.js#buildAssociatedCves' `confidenceLabel: "DIRECT"`). An inferred-only dossier can describe the CVE as "used by actors associated with this malware," never as this entity's own exploitation. */
export function checkCveExploitationByActorClaim(text, hasDirectCveAssociation) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  if (hasDirectCveAssociation || !CVE_EXPLOITATION_BY_ACTOR_LANGUAGE.test(text)) return { text, flagged: false };
  return {
    text: "Not established by available evidence: this platform's dossier has no first-party record of this entity exploiting that CVE (only an inferred, actor-derived association at most).",
    flagged: true,
  };
}

const VICTIM_TARGETING_LANGUAGE = /\btarget(s|ed|ing)?\b[^.]{0,50}\b(industry|sector|organizations? in|companies in|businesses in)\b/i;

/** Fail-closed guard for a claim that this entity targets a specific industry/sector -- requires the dossier's victimsTargeting aggregation (entityCorrelation.js#buildVictimsTargeting) to have at least one real victim record; a 0-victim dossier can never support a targeting claim, however plausible-sounding. */
export function checkVictimTargetingClaim(text, hasVictimTargetingData) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  if (hasVictimTargetingData || !VICTIM_TARGETING_LANGUAGE.test(text)) return { text, flagged: false };
  return {
    text: "Not established by available evidence: this platform's dossier has no recorded victim/targeting data supporting a specific industry or sector claim for this entity.",
    flagged: true,
  };
}

const IOC_ATTRIBUTION_LANGUAGE = /\b(associated with|linked to|attributed to|used by|belongs to|part of the infrastructure (for|of)|tied to|connected to)\b/i;

/**
 * Fail-closed guard for the IOC extraction pipeline overhaul's own "no
 * hallucinated relationships" requirement -- an indicator's own canonical
 * record (server/iocIntelligence.js) only ever carries a malware/actor/
 * campaign association when a real, code-computed co-occurrence was found
 * (see iocIntelligence.js#backfillMissingAssociations' own comment: never
 * inferred, only ever confirmed by two independent passes already
 * agreeing). If AI narrative names a real, platform-tracked entity in
 * connection with THIS indicator that the canonical record doesn't actually
 * list, that's exactly the fabricated-attribution pattern this guard exists
 * to catch -- appends a caveat rather than trusting the prose, same
 * best-effort-prose-scan shape as checkProseGrounding above, just scoped to
 * one indicator's own verified associations instead of the whole search.
 */
export function checkIocAttributionClaim(text, iocRecord) {
  if (!text || typeof text !== "string") return { text, flagged: false };
  if (!IOC_ATTRIBUTION_LANGUAGE.test(text)) return { text, flagged: false };
  const associations = iocRecord?.aggregatedAssociations;
  const knownAssociated = new Set([...(associations?.malwareFamilies ?? []), ...(associations?.actors ?? []), ...(associations?.campaigns ?? [])].map(norm));
  const lower = text.toLowerCase();
  const suspects = allKnownEntityNames().filter((name) => {
    const n = norm(name);
    if (n.length < 4 || knownAssociated.has(n)) return false;
    return lower.includes(n);
  });
  if (suspects.length === 0) return { text, flagged: false };
  return {
    text: `${text} [Caveat: this platform's canonical indicator record does not list ${suspects.slice(0, 3).join(", ")} among its verified associations -- treat any such attribution as unconfirmed.]`,
    flagged: true,
  };
}
