// Intelligence Investigation Console orchestrator -- detects the indicator
// type, routes to the matching per-type module, runs the shared cross-
// reference pass, and assembles the Universal Overview every indicator type
// shows regardless of what kind it is. This is the only place that knows
// about all indicator types; every module below it only knows its own shape.
//
// Also computes this search's seed Investigation Graph node
// (investigationGraph.js#getGraphNode) in the same pass -- previously the
// graph was a second, independent round trip the client made itself
// (GET /dashboard/investigation-graph) after resolving which node to ask
// for client-side (the old resolveGraphTarget() in
// useInvestigationWorkspace.ts, now ported here as resolveGraphTarget()
// below, since it needs moduleData which only exists inside this function).
// Folding it in here means a search never comes back "No Data" from this
// module while the graph -- which draws on the same entity stores plus
// ransomware/dark-web data -- actually has real correlation for the same
// entity.
import { detectIndicatorType, isHashType, isIpType } from "./detect.js";
import * as ipModule from "./ipModule.js";
import * as domainModule from "./domainModule.js";
import * as urlModule from "./urlModule.js";
import * as hashModule from "./hashModule.js";
import * as cveModule from "./cveModule.js";
import * as entityModule from "./entityModule.js";
import * as artifactModule from "./artifactModule.js";
import * as ransomwareGroupModule from "./ransomwareGroupModule.js";
import * as countryModule from "./countryModule.js";
import { crossReferenceIndicator } from "./crossReference.js";
import { getGraphNode } from "./investigationGraph.js";
import { resolveCanonicalAlias } from "./knownAliasGroups.js";
import { buildSearchCoverage } from "./coverage.js";
import { rankFindings } from "./rankResults.js";
import { buildEvidence } from "./evidence.js";
import { assessCveExploitationState } from "./cveExploitState.js";
import { computeVerdict } from "./verdictEngine.js";
import { buildActionabilityGuidance } from "./actionability.js";

const ARTIFACT_TYPES = new Set(["email", "fileName", "processName", "registryKey", "userAgent"]);

const DIRECT_GRAPH_TYPE = {
  cve: "cve",
  ip: "ip",
  domain: "domain",
  url: "url",
  email: "email",
  fileName: "fileName",
  processName: "processName",
  registryKey: "registryKey",
  userAgent: "userAgent",
  country: "country",
  asn: "asn",
};

/**
 * Which single graph node this search's Relationships/Recommended-Actions
 * view should center on -- IOC-shaped types map 1:1 onto a graph node type.
 * `name`-type (malware/actor/campaign search) mirrors entityModule.js's own
 * "best primary match" precedence (malware first, then APT/ransomware
 * actor, then any actor, then campaign) so the graph agrees with which
 * entity the Universal Overview's verdict was computed from. Ported from
 * the old client-side resolveGraphTarget() in useInvestigationWorkspace.ts
 * (now deleted there) -- same logic, just server-side where moduleData
 * already exists before the response is sent.
 */
function resolveGraphTarget(type, normalized, moduleData) {
  if (isHashType(type)) return { type: "hash", key: normalized };
  const direct = DIRECT_GRAPH_TYPE[type];
  if (direct) return { type: direct, key: normalized };

  if (type === "ransomwareGroup") return { type: "actor", key: normalized };

  if (type === "name") {
    if (moduleData.malware?.length > 0) return { type: "malware", key: moduleData.malware[0].entity.name };
    const primaryActor = moduleData.actors?.find((a) => a.type === "Ransomware" || a.type === "APT") ?? moduleData.actors?.[0];
    if (primaryActor) return { type: "actor", key: primaryActor.name };
    if (moduleData.campaigns?.length > 0) return { type: "campaign", key: moduleData.campaigns[0].name };
    // Nothing matched any of the three entity stores -- last resort, check
    // whether this is actually a victim organization (ransomware/dark-web
    // records key by org name, not by malware/actor/campaign name, so
    // entityModule's own search would never have found it).
    return { type: "victim", key: normalized };
  }

  return null;
}

/** Real graph node for this search, computed once and reused for both the Relationships view and Recommended Actions -- never a second fetch. Returns null only when no graph node type applies at all (shouldn't happen given resolveGraphTarget's victim fallback, but stays defensive). */
async function computeGraphResult(type, normalized, moduleData) {
  const target = resolveGraphTarget(type, normalized, moduleData);
  if (!target) return null;
  try {
    return await getGraphNode(target.type, target.key);
  } catch {
    return null; // graph computation failing (e.g. a live DNS/RIPEstat call throwing) should never fail the whole investigation
  }
}

function mostRecent(...dates) {
  const valid = dates.filter(Boolean).map((d) => new Date(d)).filter((d) => !Number.isNaN(d.getTime()));
  if (valid.length === 0) return null;
  return new Date(Math.max(...valid.map((d) => d.getTime()))).toISOString();
}

function earliest(...dates) {
  const valid = dates.filter(Boolean).map((d) => new Date(d)).filter((d) => !Number.isNaN(d.getTime()));
  if (valid.length === 0) return null;
  return new Date(Math.min(...valid.map((d) => d.getTime()))).toISOString();
}

function firstLastSeenFor(type, moduleData) {
  if (type === "cve") return { firstSeen: moduleData.cve?.publishedDate ?? null, lastSeen: null };
  if (type === "name") {
    const primary = moduleData.malware?.[0]?.entity ?? moduleData.actors?.[0] ?? moduleData.campaigns?.[0] ?? null;
    return { firstSeen: primary?.firstSeen ?? null, lastSeen: primary?.lastSeen ?? null };
  }
  if (ARTIFACT_TYPES.has(type)) {
    const hit = moduleData.crossReference?.relatedIocs?.[0];
    return { firstSeen: hit?.firstSeen ?? null, lastSeen: null };
  }
  // ip/domain/url/hash: best-effort across whatever lookup sources reported a date
  const results = moduleData.lookupResults ?? [];
  const dates = results.flatMap((r) => [r.firstSubmitted, r.firstSeen, r.lastSeen].filter(Boolean));
  return { firstSeen: earliest(...dates), lastSeen: mostRecent(...dates) };
}

function mitreMappingFor(type, moduleData, crossRef) {
  if (type === "cve") return (moduleData.profile?.relatedTechniques ?? []).map((t) => ({ id: t.id, name: t.name, tactic: t.tactic }));
  if (type === "name" && moduleData.actors?.length) {
    return (moduleData.actors[0].techniqueIds ?? []).map((id) => ({ id, name: id, tactic: null }));
  }
  return [];
}

// Merges back the one or two per-source raw results a type module filters
// OUT of its own returned `lookupResults` for DISPLAY reasons (RDAP is
// shown in its own Registration section, not Source Breakdown noise; the
// same for urlscan.io's own Scan section) -- Evidence Reconciliation still
// needs the full raw set, since RDAP/urlscan.io are real evidence sources
// (contextual and direct respectively, see evidence.js), just not ones the
// Source Breakdown list repeats.
function allLookupResults(type, moduleData) {
  const base = Array.isArray(moduleData?.lookupResults) ? moduleData.lookupResults : [];
  if (type === "domain" && moduleData?.registration) return [...base, moduleData.registration];
  if (type === "url" && moduleData?.scan) return [...base, moduleData.scan];
  return base;
}

/**
 * The shared pipeline every entity type routes through: Source Evidence
 * (moduleData/lookupResults, already gathered by the type module) ->
 * Evidence Reconciliation (evidence.js) -> Correlation (already folded in
 * via crossRef/graph, computed by the caller) -> Contextual Assessment ->
 * Confidence -> Severity/Priority (verdictEngine.js, combined into one
 * VerdictResult) -> Actionable Guidance (actionability.js). AI Analysis
 * (GraphInsights/CorrelationSummary/AiInvestigationReport) stays a separate,
 * later stage -- auto-triggered or on-demand client-side, reading this
 * result's `overview.verdict`/`overview.cveExploitationState` once built.
 */
function assemble(indicator, type, moduleData, crossRef, graph, resolvedCanonicalName = null, cveExploitationState = null) {
  const { firstSeen, lastSeen } = firstLastSeenFor(type, moduleData);

  const evidence = buildEvidence({ type, lookupResults: allLookupResults(type, moduleData), crossRef, moduleData, cveExploitationState });
  const verdict = computeVerdict({ entityType: type, evidence, cveExploitationState, context: { moduleData, crossRef, graph } });
  const actionability = buildActionabilityGuidance({ type, indicator, verdict, moduleData, cveExploitationState, graph });

  const overview = {
    indicator,
    indicatorType: type,
    verdict,
    cveExploitationState,
    firstSeen,
    lastSeen,
    activeCampaigns: crossRef?.activeCampaigns ?? (type === "name" ? (moduleData.campaigns ?? []).map((c) => c.name) : []),
    associatedThreatActors: crossRef?.associatedThreatActors ?? (type === "name" ? (moduleData.actors ?? []).map((a) => a.name) : []),
    mitreAttackMapping: mitreMappingFor(type, moduleData, crossRef),
    businessImpact: null, // populated once "Generate AI Report" runs -- see server/investigationAi.js
    aiInvestigationSummary: null,
  };

  return {
    indicator,
    type,
    overview,
    moduleData,
    relatedIntelligence: crossRef
      ? {
          matchedMalwareFamilies: crossRef.matchedMalwareFamilies,
          associatedThreatActors: crossRef.associatedThreatActors,
          activeCampaigns: crossRef.activeCampaigns,
          matchingAiReports: crossRef.matchingAiReports,
          relatedIocs: crossRef.relatedIocs,
        }
      : type === "name"
        ? { matchedMalwareFamilies: (moduleData.malware ?? []).map((m) => m.entity.name), associatedThreatActors: (moduleData.actors ?? []).map((a) => a.name), activeCampaigns: (moduleData.campaigns ?? []).map((c) => c.name), matchingAiReports: [], relatedIocs: [] }
        : null,
    notConfigured: moduleData.notConfigured ?? [],
    rateLimited: moduleData.rateLimited ?? [],
    skipped: moduleData.skipped ?? [],
    graph,
    coverage: buildSearchCoverage(type, moduleData, crossRef, graph),
    rankedFindings: rankFindings(graph, crossRef),
    resolvedCanonicalName,
    actionability,
  };
}

/** @returns {Promise<import("../../src/types/threat-intel.js").InvestigationResult>} */
export async function investigate(rawValue) {
  const { type, normalized } = detectIndicatorType(rawValue);

  // For every type except "name", the graph target doesn't depend on the
  // type module's own result (resolveGraphTarget only needs moduleData for
  // the "name" case's malware/actor/campaign precedence) -- so the type
  // module and the graph computation run in parallel, not sequentially.
  if (type === "cve") {
    const [data, graph] = await Promise.all([cveModule.gather(normalized), computeGraphResult("cve", normalized, {})]);
    const cveExploitationState = data.found ? assessCveExploitationState({ cve: data.cve, profile: data.profile }) : null;
    return assemble(normalized, "cve", data, null, graph, null, cveExploitationState);
  }
  if (isIpType(type)) {
    const [data, graph] = await Promise.all([ipModule.gather(normalized), computeGraphResult("ip", normalized, {})]);
    return assemble(normalized, "ip", data, crossReferenceIndicator(normalized), graph);
  }
  if (type === "domain") {
    const [data, graph] = await Promise.all([domainModule.gather(normalized), computeGraphResult("domain", normalized, {})]);
    return assemble(normalized, "domain", data, crossReferenceIndicator(normalized), graph);
  }
  if (type === "url") {
    const [data, graph] = await Promise.all([urlModule.gather(normalized), computeGraphResult("url", normalized, {})]);
    return assemble(normalized, "url", data, crossReferenceIndicator(normalized), graph);
  }
  if (isHashType(type)) {
    const [data, graph] = await Promise.all([hashModule.gather(normalized, type), computeGraphResult(type, normalized, {})]);
    return assemble(normalized, type, data, crossReferenceIndicator(normalized), graph);
  }
  if (type === "ransomwareGroup") {
    const [data, graph] = await Promise.all([ransomwareGroupModule.gather(normalized), computeGraphResult("ransomwareGroup", normalized, {})]);
    return assemble(normalized, "ransomwareGroup", data, data.crossReference, graph);
  }
  if (type === "country") {
    const [data, graph] = await Promise.all([countryModule.gather(normalized), computeGraphResult("country", normalized, {})]);
    return assemble(normalized, "country", data, data.crossReference, graph);
  }
  if (type === "asn") {
    const graph = await computeGraphResult("asn", normalized, {});
    return assemble(normalized, "asn", {}, null, graph);
  }
  if (type === "name") {
    // Resolve a known alias (e.g. "Cozy Bear" -> "APT29", "Qbot" -> "QakBot")
    // to the canonical entity name BEFORE searching, so the search continues
    // under whichever name this platform actually tracks -- see
    // knownAliasGroups.js. `indicator` (what's shown as the searched value)
    // stays the analyst's original typed value; `resolvedCanonicalName`
    // holds the canonical name it was resolved TO, for an honest "Searched
    // as X (you searched Y)" note -- null unless a real resolution happened.
    const canonical = resolveCanonicalAlias(normalized);
    const searchValue = canonical ?? normalized;
    // Genuinely sequential -- the graph target for a name search depends on
    // which of the three entity stores (or none) entityModule matched.
    const data = await entityModule.gather(searchValue);
    const graph = await computeGraphResult("name", searchValue, data);
    return assemble(normalized, "name", data, null, graph, canonical);
  }
  // email / fileName / processName / registryKey / userAgent -- cross-reference-only
  const [data, graph] = await Promise.all([artifactModule.gather(normalized, type), computeGraphResult(type, normalized, {})]);
  return assemble(normalized, type, data, data.crossReference, graph);
}

export { detectIndicatorType };
