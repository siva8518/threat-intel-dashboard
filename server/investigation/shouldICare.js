// "Should I Care?" -- the analyst-facing SO WHAT layer, replacing the old
// source-first sentence ("VirusTotal reports malicious...", "OTX reports
// suspicious...") this section used to show directly from
// verdictEngine.js#buildReasoning. An analyst doesn't care that a named
// tool said something; they care what the indicator represents, how strong
// and how CONSISTENT the evidence is, whether there's a real malware/actor/
// campaign/victim association, whether it's shared/cloud/VPN infrastructure
// that could be a false positive, whether it's relevant to THEIR
// environment, and what to do next. This module produces exactly that,
// structured around three explicit, clearly-separated layers requested for
// this feature:
//   EXTERNAL INTELLIGENCE -- what has been reported about this indicator
//     out in the world (reputation + behavioral + threat-context evidence,
//     synthesized -- never source-name-first).
//   ORGANIZATIONAL RISK -- whether it's known to have touched THIS
//     environment. Always the honest "cannot be determined" statement today
//     (this platform has no SIEM/EDR/network-telemetry integration) --
//     computed in code, never left to the model to invent or imply.
//   ANALYST ACTION -- a concrete next step, grounded in the two layers
//     above, not a generic "investigate the IOC."
// Same hybrid-grounding discipline as graphInsights.js/correlationSummary.js:
// every countable/classified fact (evidence items, their categories,
// attribution, shared-infrastructure detection, the deterministic
// analystDecision/blockRecommendation) is computed in JS BEFORE the model
// sees it -- the model's only job is turning already-correct facts into one
// coherent, human-centric narrative, never deciding the verdict or
// inventing a relationship/attribution/environmental-impact claim itself.
import { aiRouter } from "../ai/aiRouter.js";
import { hasSharedInfrastructureSignal, hasKnownAttribution } from "./verdictEngine.js";
import { checkProseGrounding, checkCveExploitationClaim, checkUnsupportedClaims } from "./groundClaims.js";

// No SIEM/EDR/network-telemetry integration exists anywhere in this
// platform (confirmed -- see server/investigation/ipModule.js's own
// `internalInvestigation` placeholder, the only per-type module that even
// has a field for this). Generalized here so every entity type gets the
// same honest statement instead of only IP searches.
const ENVIRONMENTAL_RELEVANCE_UNKNOWN =
  "Cannot currently be determined -- this platform has no connected SIEM/EDR/network-telemetry integration, so it cannot tell you whether this indicator has actually been observed in your environment. The next step is to check your own logs for it.";

function evidenceBullets(evidence) {
  return evidence.items.filter((i) => i.category !== "conflicting").map((i) => `${i.source}: ${i.claim}`);
}

function infrastructureNote(evidence) {
  if (!hasSharedInfrastructureSignal(evidence)) return null;
  return "This indicator sits on known shared/cloud/CDN/VPN/datacenter infrastructure -- ownership of that infrastructure is context, not evidence of malicious activity. Legitimate and malicious tenants both use it; attribution requires more than IP/ASN ownership.";
}

const SYSTEM_PROMPT =
  "You are a senior Threat Intelligence Analyst writing the \"Should I Care?\" assessment for another analyst who just searched an indicator or entity in this platform. " +
  "You are given the already-computed, authoritative verdict (state/severity/confidence/analystDecision -- these are FINAL, you do not recompute or second-guess them), every real evidence item already classified into categories (direct/corroborating/indirect/contextual/negative/conflicting/attribution), real relationship/attribution data (actors/campaigns/malware/victims/techniques), whether this indicator sits on shared/cloud/VPN infrastructure, and this platform's real environmental-telemetry status. " +
  "\n\nYOUR JOB: produce a human-centric analyst narrative in exactly the schema below. Never lead with a source name (\"VirusTotal reports...\", \"OTX says...\") -- lead with the conclusion; sources support it, they are not the subject of the sentence. Never treat reputation alone as proof of anything -- distinguish a bare reputation SCORE from actual BEHAVIORAL evidence (e.g. \"SSH brute-force activity\") from real THREAT CONTEXT (a named malware/actor/campaign) -- these are not equivalent and must not be blended into one undifferentiated claim of severity. " +
  "\n\nGROUNDING RULES:\n" +
  "- Every claim must trace to a specific evidence item, relationship, or field you were given. Never invent a count, a relationship, or a claim not present in the data.\n" +
  "- Reputation signals alone (abuse-report scores, community pulse mentions, bare detection counts) must never be narrated as if they were confirmed malicious behavior or attribution -- describe what was actually reported (e.g. \"reputation sources report suspicious network scanning activity\"), not a conclusion those sources didn't establish.\n" +
  "- Shared/cloud/CDN/VPN/datacenter infrastructure ownership is NEVER evidence of malicious activity -- if infrastructureContext is present, acknowledge it explicitly as a reason for caution, not as something to ignore.\n" +
  "- Never claim this indicator is confirmed C2, belongs to a named threat actor, or is part of a named ransomware campaign unless hasAttribution is true in the data you were given.\n" +
  "- Never claim this indicator is attacking, has compromised, or is otherwise confirmed active against the analyst's own environment -- environmentalRelevance is always \"cannot be determined\" unless real telemetry data says otherwise, and you were told which applies here.\n" +
  "- Never state a CVE is actively/confirmed exploited from CVSS, EPSS, or exploit-availability alone -- only from the provided cveExploitationState.\n" +
  "- Your narrative must be CONSISTENT with the provided analystDecision -- do not imply more or less urgency than that decision reflects.\n" +
  "- Do not restate the evidenceBullets list verbatim -- the analyst can already see it below your narrative. Synthesize what it means, don't enumerate it again.\n" +
  "\n\nRespond with ONLY a single JSON object with exactly these top-level keys:\n" +
  '"headline": string -- ONE sentence, the analyst-facing bottom line (e.g. "Investigate if observed internally -- strong external reputation evidence, but no confirmed attribution and possible shared infrastructure."). Must agree with the provided analystDecision.\n' +
  '"externalIntelligence": string -- 2-4 sentences synthesizing what has actually been reported about this indicator out in the world: reputation signal strength/consistency, any real behavioral evidence, and any real threat-context (malware/actor/campaign) -- clearly distinguishing which of those apply here, never source-name-first, never overstating a bare reputation score into a certainty.\n' +
  '"analystAction": string -- 2-4 sentences: a CONCRETE next step grounded in the external intelligence and the fact that organizational relevance is unknown (e.g. what to search for in the analyst\'s own logs, which service/host type to prioritize) -- never a generic "investigate the IOC" line.\n' +
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
  const { overview, graph, relatedIntelligence } = result;
  const verdict = overview.verdict;
  const evidence = verdict.evidence;

  const relatedActors = (graph?.edges ?? []).filter((e) => e.targetType === "actor").map((e) => e.targetLabel);
  const relatedCampaigns = (graph?.edges ?? []).filter((e) => e.targetType === "campaign").map((e) => e.targetLabel);
  const relatedMalware = (graph?.edges ?? []).filter((e) => e.targetType === "malware").map((e) => e.targetLabel);
  const victimsTargeted = (graph?.edges ?? []).filter((e) => e.targetType === "victim").map((e) => e.targetLabel);
  const attackTechniques = (graph?.edges ?? []).filter((e) => e.targetType === "attackTechnique").map((e) => e.targetLabel);

  const attributed = hasKnownAttribution(evidence);
  const sharedInfra = hasSharedInfrastructureSignal(evidence);
  const infraNote = infrastructureNote(evidence);
  const bullets = evidenceBullets(evidence);

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
    hasAttribution: attributed,
    sharedInfrastructureDetected: sharedInfra,
    relatedActors,
    relatedCampaigns,
    relatedMalware,
    victimsTargeted,
    attackTechniques,
    matchingAiReportCount: relatedIntelligence?.matchingAiReports?.length ?? 0,
    environmentalRelevance: hasEnvironmentalTelemetry ? "known" : "cannot be determined -- no SIEM/EDR/network-telemetry integration",
  };
  const userPrompt = `INDICATOR ASSESSMENT INPUT (verified by this platform, not model-generated):\n${JSON.stringify(context, null, 2)}\n\nProduce the JSON "Should I Care?" assessment described in your instructions.`;

  const response = await aiRouter.summarizeJson(userPrompt, { systemPrompt: SYSTEM_PROMPT, temperature: 0.3 });
  const parsed = parseModelReport(response.summary);
  if (!parsed) throw new Error('"Should I Care?": model response was not valid JSON');

  const allowedNames = [overview.indicator, ...relatedActors, ...relatedCampaigns, ...relatedMalware, ...victimsTargeted];
  const groundingContext = { hasAttribution: attributed, hasEnvironmentalTelemetry };
  const ground = (text) => checkUnsupportedClaims(checkCveExploitationClaim(checkProseGrounding(text, allowedNames).text, overview.cveExploitationState).text, groundingContext).text;

  return {
    headline: ground(safeString(parsed.headline, `${verdict.analystDecision} -- see evidence below.`)),
    analystDecision: verdict.analystDecision,
    externalIntelligence: ground(safeString(parsed.externalIntelligence, "Not enough data to characterize external intelligence for this indicator.")),
    evidenceBullets: bullets,
    infrastructureNote: infraNote,
    organizationalRisk: hasEnvironmentalTelemetry ? safeString(parsed.organizationalRisk, ENVIRONMENTAL_RELEVANCE_UNKNOWN) : ENVIRONMENTAL_RELEVANCE_UNKNOWN,
    analystAction: ground(safeString(parsed.analystAction, "Insufficient evidence to recommend a specific next step -- re-check if new context emerges.")),
    model: response.model,
    provider: response.provider,
    generatedAt: new Date().toISOString(),
  };
}
