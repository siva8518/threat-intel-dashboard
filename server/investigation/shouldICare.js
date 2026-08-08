// "Should I Care?" -- the analyst-facing synthesis layer that sits ABOVE the
// per-source Evidence Cards (evidence.cards, rendered directly by
// EvidencePanel.tsx). It never restates what each source found -- the cards
// already show that individually, one per source, including explicit "No
// finding" entries. This module answers the question the cards alone can't:
// what does the COMBINED picture mean, is there a specific malicious intent
// the evidence actually supports, is this indicator known to be relevant to
// THIS environment, and what should the analyst do next. Four explicit,
// non-overlapping sections:
//   COMBINED INTELLIGENCE ASSESSMENT -- what the evidence indicates once
//     compared: how strong/consistent it is, how conflicts were resolved (if
//     any), whether shared/cloud/CDN/VPN infrastructure tempers the read,
//     and whether multiple "sources" are actually independent or the same
//     underlying report redistributed.
//   LIKELY MALICIOUS INTENT -- only populated when evidence genuinely
//     supports a specific intent (real attribution, or direct behavioral/
//     malware-association evidence) -- never inferred from bare reputation
//     scores, ASN/cloud ownership, domain-naming patterns, or multi-domain
//     resolution alone. Fail-closed enforced in code (see
//     groundClaims.js#checkMaliciousIntentClaim), not just prompted.
//   ENVIRONMENTAL RELEVANCE -- whether it's known to have touched THIS
//     environment. Always the honest "cannot be determined" statement today
//     (this platform has no SIEM/EDR/network-telemetry integration) --
//     computed in code, never left to the model to invent or imply.
//   NEXT ACTION -- a concrete next step, grounded in the three sections
//     above, not a generic "investigate the IOC."
// Same hybrid-grounding discipline as graphInsights.js/correlationSummary.js:
// every countable/classified fact (evidence items and cards, their
// categories, attribution, shared-infrastructure detection, source
// independence, the deterministic analystDecision) is computed in JS BEFORE
// the model sees it -- the model's only job is turning already-correct facts
// into coherent prose, never deciding the verdict or inventing a
// relationship/attribution/intent/environmental-impact claim itself.
import { aiRouter } from "../ai/aiRouter.js";
import { hasSharedInfrastructureSignal, hasKnownAttribution } from "./verdictEngine.js";
import { checkProseGrounding, checkCveExploitationClaim, checkUnsupportedClaims, checkMaliciousIntentClaim, checkCampaignInvolvementClaim, checkCveExploitationByActorClaim, checkVictimTargetingClaim } from "./groundClaims.js";

// No SIEM/EDR/network-telemetry integration exists anywhere in this
// platform (confirmed -- see server/investigation/ipModule.js's own
// `internalInvestigation` placeholder, the only per-type module that even
// has a field for this). Generalized here so every entity type gets the
// same honest statement instead of only IP searches.
const ENVIRONMENTAL_RELEVANCE_UNKNOWN =
  "Cannot currently be determined -- this platform has no connected SIEM/EDR/network-telemetry integration, so it cannot tell you whether this indicator has actually been observed in your environment. The next step is to check your own logs for it.";

// Sources whose findings describe a SPECIFIC observed behavior or a real
// malware/campaign/victim association -- as opposed to a bare reputation
// score or detection count. Only these (plus real attribution) can ever
// justify populating "Likely Malicious Intent" -- deliberately excludes
// AbuseIPDB/VirusTotal/GreyNoise/OTX/Pulsedive/MISP, all of which are
// reputation-flavored and, per this platform's explicit rule, must never
// alone be read as evidence of a specific intent.
const INTENT_SUPPORTING_SOURCES = new Set(["Hybrid Analysis", "urlscan.io", "SANS ISC", "LeakIX", "Team Cymru MHR", "CISA KEV", "Ransomware Victim Tracking (ransomware.live / RansomWatch / RansomLook)"]);

function hasIntentSupportingEvidence(evidence) {
  if (hasKnownAttribution(evidence)) return true;
  return evidence.items.some((i) => (i.category === "direct" || i.category === "corroborating") && INTENT_SUPPORTING_SOURCES.has(i.source));
}

// Only surfaced when a genuine majority of this entity's own tracked
// victims fall in one industry (>=50%, at least 3 victims so 1-of-1 doesn't
// read as a "pattern") -- computed here in JS from the dossier's own real
// byIndustry tally (entityCorrelation.js#buildVictimsTargeting), never left
// for the model to eyeball from a raw list.
function victimIndustryConcentrationFor(dossier) {
  const byIndustry = dossier?.victimsTargeting?.byIndustry ?? [];
  const total = dossier?.victimsTargeting?.totalVictims ?? 0;
  if (total < 3 || byIndustry.length === 0) return null;
  const top = byIndustry[0];
  const share = top.count / total;
  if (share < 0.5) return null;
  return { industry: top.industry, count: top.count, totalVictims: total, sharePercent: Math.round(share * 100) };
}

function infrastructureNote(evidence) {
  if (!hasSharedInfrastructureSignal(evidence)) return null;
  return "This indicator sits on known shared/cloud/CDN/VPN/datacenter infrastructure -- ownership of that infrastructure is context, not evidence of malicious activity. Legitimate and malicious tenants both use it; attribution requires more than IP/ASN ownership.";
}

const SYSTEM_PROMPT =
  "You are a senior Threat Intelligence Analyst writing the synthesis layer that sits ABOVE a per-source evidence card grid another analyst can already see individually (one card per source, including explicit \"No finding\" cards) -- your job is NOT to restate what each source found, it is to explain what the COMBINED picture means. " +
  "You are given the already-computed, authoritative verdict (state/severity/confidence/analystDecision -- these are FINAL, you do not recompute or second-guess them), every real evidence item already classified into categories (direct/corroborating/indirect/contextual/negative/conflicting/attribution), whether sources are independent or redistributing the same underlying report, whether this indicator sits on shared/cloud/VPN infrastructure, whether real attribution/behavioral evidence exists (hasIntentEvidence), real relationship data (actors/campaigns/malware/victims/techniques), and this platform's real environmental-telemetry status. " +
  "\n\nYOUR JOB: produce a human-centric analyst synthesis in exactly the schema below. Never lead with a source name (\"VirusTotal reports...\", \"OTX says...\") -- lead with the conclusion. Never treat reputation alone as proof of anything -- distinguish a bare reputation SCORE from actual BEHAVIORAL evidence from real THREAT CONTEXT (a named malware/actor/campaign); these are not equivalent. " +
  "\n\nGROUNDING RULES:\n" +
  "- Every claim must trace to a specific evidence item, relationship, or field you were given. Never invent a count, a relationship, or a claim not present in the data.\n" +
  "- If hasConflict is true, your combinedAssessment MUST explain what conflicts and why (e.g. one source flags malicious while another reports clean/benign) -- never just say \"conflicting intelligence\" and stop.\n" +
  "- If independentSourceCount is meaningfully lower than sourceCount, note that some of the apparent agreement may be the same underlying report counted more than once -- do not describe repeated/redistributed feeds as independent confirmation.\n" +
  "- Shared/cloud/CDN/VPN/datacenter infrastructure ownership is NEVER evidence of malicious activity -- if infrastructureContext is present, acknowledge it explicitly as a reason for caution, not as something to ignore.\n" +
  "- likelyMaliciousIntent: if hasIntentEvidence is false, you MUST write exactly this sentence and nothing else: \"Not established from available intelligence -- insufficient evidence to determine intent.\" Do NOT infer intent from VirusTotal/AbuseIPDB detection counts, cloud/ASN/hosting-provider membership, domain-naming patterns, multi-domain resolution, or \"this ASN has malicious activity elsewhere\" -- none of those establish intent. If hasIntentEvidence is true, describe the SPECIFIC type of malicious activity the real evidence supports (e.g. \"credential-harvesting infrastructure\", \"SSH brute-force scanning\", \"malware C2 for the X family\") -- never a generic \"this is malicious.\"\n" +
  "- Never claim this indicator is confirmed C2, belongs to a named threat actor, or is part of a named ransomware campaign unless hasAttribution is true in the data you were given.\n" +
  "- Never claim this indicator is attacking, has compromised, or is otherwise confirmed active against the analyst's own environment -- environmentalRelevance is computed separately and always \"cannot be determined\" unless real telemetry says otherwise.\n" +
  "- Never state a CVE is actively/confirmed exploited from CVSS, EPSS, or exploit-availability alone -- only from the provided cveExploitationState.\n" +
  "- Your synthesis must be CONSISTENT with the provided analystDecision -- do not imply more or less urgency than that decision reflects.\n" +
  "- For an entity-type search (a threat actor/malware family/ransomware group/campaign, indicated by hasVerifiedEntityProfile being non-null) your combinedAssessment should read differently than for a bare IOC: if hasVerifiedEntityProfile is true, ground the assessment in the entity's real correlated profile depth (not just a reputation verdict); if false but victim disclosures still exist, say so plainly (a tracked ransomware group with disclosed victims but no deeper platform-verified profile) rather than implying more is known than the data supports. If victimIndustryConcentration is present, you may note the concentration as a targeting pattern -- but only if it's genuinely present in the data.\n" +
  "- RECENCY: you may also be given `recentActivity` -- what this entity has ACTUALLY done in the last `recentActivity.windowDays` days, separate from its all-time profile. This platform has a confirmed history of over-broad, stale summaries (e.g. \"targets all industries\") burying a specific recent development -- your combinedAssessment and nextAction must prioritize `recentActivity` when `hasRecentSignal` is true (name the actual recent industry/country/CVE/victim, don't generalize it away), and explicitly say so when it's false (no recent activity found in the tracked window) rather than silently falling back to the all-time picture. Never describe something as \"recent\"/\"current\"/\"ongoing\" unless it's actually in `recentActivity`.\n" +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"combinedAssessment": string -- 2-4 sentences synthesizing what the evidence indicates ONCE COMPARED: overall strength/consistency, how any conflict was resolved or why it remains unresolved, whether apparent multi-source agreement is genuinely independent, and how shared-infrastructure context (if any) tempers the read. Never source-name-first, never restate the raw evidence list.\n' +
  '"likelyMaliciousIntent": string -- 1-3 sentences. Follow the grounding rule above exactly.\n' +
  '"nextAction": string -- 2-4 sentences: a CONCRETE next step grounded in the assessment above and the fact that environmental relevance is unknown (e.g. what to search for in the analyst\'s own logs, which service/host type to prioritize) -- never a generic "investigate the IOC" line.\n' +
  "No other text, no markdown formatting, no code fences.";

function safeString(value, fallback) {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
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
export async function generateShouldICare(result) {
  const { overview, graph, relatedIntelligence, moduleData } = result;
  const verdict = overview.verdict;
  const evidence = verdict.evidence;
  const dossier = moduleData?.dossier ?? null;

  const relatedActors = (graph?.edges ?? []).filter((e) => e.targetType === "actor").map((e) => e.targetLabel);
  const relatedCampaigns = (graph?.edges ?? []).filter((e) => e.targetType === "campaign").map((e) => e.targetLabel);
  const relatedMalware = (graph?.edges ?? []).filter((e) => e.targetType === "malware").map((e) => e.targetLabel);
  const victimsTargeted = (graph?.edges ?? []).filter((e) => e.targetType === "victim").map((e) => e.targetLabel);
  const attackTechniques = (graph?.edges ?? []).filter((e) => e.targetType === "attackTechnique").map((e) => e.targetLabel);

  const attributed = hasKnownAttribution(evidence);
  const sharedInfra = hasSharedInfrastructureSignal(evidence);
  const infraNote = infrastructureNote(evidence);
  const intentEvidence = hasIntentSupportingEvidence(evidence);

  // Real telemetry never exists today (see ENVIRONMENTAL_RELEVANCE_UNKNOWN's
  // own comment) -- this stays a boolean input rather than a hardcoded
  // assumption so a future real SIEM/EDR integration only needs to flip
  // this one value, not rewrite this module's logic.
  const hasEnvironmentalTelemetry = false;

  const context = {
    entity: { type: overview.indicatorType, label: overview.indicator },
    verdict: {
      state: verdict.state,
      label: verdict.label,
      severity: verdict.severity,
      confidence: verdict.confidence,
      analystDecision: verdict.analystDecision,
      conflicts: verdict.conflicts,
    },
    cveExploitationState: overview.cveExploitationState ? { state: overview.cveExploitationState.state, label: overview.cveExploitationState.label, reasoning: overview.cveExploitationState.reasoning } : null,
    evidenceByCategory: {
      direct: evidence.items.filter((i) => i.category === "direct").map((i) => i.claim),
      corroborating: evidence.items.filter((i) => i.category === "corroborating").map((i) => i.claim),
      indirect: evidence.items.filter((i) => i.category === "indirect").map((i) => i.claim),
      negative: evidence.items.filter((i) => i.category === "negative").map((i) => i.claim),
      attribution: evidence.items.filter((i) => i.category === "attribution").map((i) => i.claim),
    },
    hasConflict: evidence.hasConflict,
    conflictDescription: evidence.conflictDescription,
    sourceCount: evidence.sourceCount,
    independentSourceCount: evidence.independentSourceCount,
    hasAttribution: attributed,
    hasIntentEvidence: intentEvidence,
    sharedInfrastructureDetected: sharedInfra,
    relatedActors,
    relatedCampaigns,
    relatedMalware,
    victimsTargeted,
    attackTechniques,
    matchingAiReportCount: relatedIntelligence?.matchingAiReports?.length ?? 0,
    environmentalRelevance: hasEnvironmentalTelemetry ? "known" : "cannot be determined -- no SIEM/EDR/network-telemetry integration",
    // null for IOC-type searches (no dossier at all); for an entity search,
    // true only when this platform matched a real verified malware/actor/
    // campaign profile (entityCorrelation.js `sourceType === "verified-profile"`),
    // not merely a bare ransomware-tracker group name.
    hasVerifiedEntityProfile: dossier ? dossier.sourceType === "verified-profile" : null,
    victimIndustryConcentration: victimIndustryConcentrationFor(dossier),
    // What this entity has ACTUALLY done recently -- see the RECENCY rule
    // above and server/investigation/entityCorrelation.js#buildRecentActivity.
    // null for IOC-type searches (no dossier at all).
    recentActivity: dossier?.recentActivity ?? null,
  };
  const userPrompt = `INDICATOR ASSESSMENT INPUT (verified by this platform, not model-generated):\n${JSON.stringify(context, null, 2)}\n\nProduce the JSON "Should I Care?" synthesis described in your instructions.`;

  const response = await aiRouter.summarizeJson(userPrompt, { systemPrompt: SYSTEM_PROMPT, temperature: 0.3 });
  const parsed = parseModelReport(response.summary);
  if (!parsed) throw new Error('"Should I Care?": model response was not valid JSON');

  const allowedNames = [
    overview.indicator,
    ...relatedActors,
    ...relatedCampaigns,
    ...relatedMalware,
    ...victimsTargeted,
    ...(dossier?.recentActivity?.malwareUsed ?? []),
    ...(dossier?.recentActivity?.recentCampaigns ?? []),
    ...(dossier?.recentActivity?.recentVictims ?? []).map((v) => v.victim),
  ];
  const groundingContext = { hasAttribution: attributed, hasEnvironmentalTelemetry };
  // No-op (always true) for indicator types with no dossier at all -- see
  // the matching comment in correlationSummary.js.
  const hasCampaignData = dossier ? dossier.campaignCount > 0 : true;
  const hasDirectCveAssociation = dossier ? dossier.associatedCves.some((c) => c.confidenceLabel === "DIRECT") : true;
  const hasVictimTargetingData = dossier ? dossier.victimsTargeting.totalVictims > 0 : true;
  const ground = (text) => {
    let out = checkProseGrounding(text, allowedNames).text;
    out = checkCveExploitationClaim(out, overview.cveExploitationState).text;
    out = checkUnsupportedClaims(out, groundingContext).text;
    out = checkCampaignInvolvementClaim(out, hasCampaignData).text;
    out = checkCveExploitationByActorClaim(out, hasDirectCveAssociation).text;
    out = checkVictimTargetingClaim(out, hasVictimTargetingData).text;
    return out;
  };

  const combinedAssessment = ground(safeString(parsed.combinedAssessment, "Not enough data to characterize the combined intelligence picture for this indicator."));
  const rawIntent = safeString(parsed.likelyMaliciousIntent, null);
  const likelyMaliciousIntent = checkMaliciousIntentClaim(rawIntent ? ground(rawIntent) : rawIntent, intentEvidence).text;
  const nextAction = ground(safeString(parsed.nextAction, "Insufficient evidence to recommend a specific next step -- re-check if new context emerges."));

  return {
    analystDecision: verdict.analystDecision,
    combinedAssessment: infraNote ? `${combinedAssessment} ${infraNote}` : combinedAssessment,
    likelyMaliciousIntent,
    environmentalRelevance: hasEnvironmentalTelemetry ? safeString(parsed.environmentalRelevance, ENVIRONMENTAL_RELEVANCE_UNKNOWN) : ENVIRONMENTAL_RELEVANCE_UNKNOWN,
    nextAction,
    model: response.model,
    provider: response.provider,
    generatedAt: new Date().toISOString(),
  };
}
