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
import { getGraphNode, getExpandedGraph } from "./investigationGraph.js";
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

  // `dossier.primaryEntity` (entityCorrelation.js#pickPrimaryEntity) is now
  // the ONE shared precedence both `name` and `ransomwareGroup` searches
  // agree on -- malware first, then a Ransomware/APT actor, then any actor,
  // then a campaign -- computed once in the dossier both entityModule.js
  // and ransomwareGroupModule.js attach, instead of two separate,
  // previously-drifting implementations here.
  if (type === "ransomwareGroup") {
    const primary = moduleData.dossier?.primaryEntity;
    if (primary) return { type: primary.type, key: primary.name };
    return { type: "actor", key: normalized };
  }

  if (type === "name") {
    const primary = moduleData.dossier?.primaryEntity;
    if (primary) return { type: primary.type, key: primary.name };
    // Nothing matched any of the three entity stores -- last resort, check
    // whether this is actually a victim organization (ransomware/dark-web
    // records key by org name, not by malware/actor/campaign name, so
    // entityModule's own search would never have found it).
    return { type: "victim", key: normalized };
  }

  return null;
}

// Entity-type searches (name/ransomwareGroup -- an actor/malware/campaign/
// ransomware-group name) auto-expand 2 hops server-side so the Investigation
// Graph opens already showing the searched entity's own real relationships
// PLUS one hop beyond its strongest-confidence ones, instead of requiring
// the analyst to click every hop manually -- see
// investigationGraph.js#getExpandedGraph. IOC-type searches (ip/domain/hash/
// etc.) keep today's single-hop `getGraphNode` behavior unchanged -- several
// of those trigger live network calls per node, and fanning that out
// automatically was never part of this change's scope.
const AUTO_EXPAND_GRAPH_TYPES = new Set(["name", "ransomwareGroup"]);

/** Real graph node for this search, computed once and reused for both the Relationships view and Recommended Actions -- never a second fetch. Returns null only when no graph node type applies at all (shouldn't happen given resolveGraphTarget's victim fallback, but stays defensive). */
async function computeGraphResult(type, normalized, moduleData) {
  const target = resolveGraphTarget(type, normalized, moduleData);
  if (!target) return null;
  try {
    if (AUTO_EXPAND_GRAPH_TYPES.has(type)) return await getExpandedGraph(target.type, target.key);
    // Hash searches: pass the live-detected malware family (if any) through
    // to the graph so it can pivot into that family's full tracked profile
    // -- see investigationGraph.js#gatherCrossReferenceOnly. Every other
    // type ignores an empty context object.
    const context = isHashType(type) ? { malwareFamily: moduleData?.malwareFamily ?? null, malwareFamilySource: moduleData?.malwareFamilySource ?? null } : {};
    return await getGraphNode(target.type, target.key, context);
  } catch {
    return null; // graph computation failing (e.g. a live DNS/RIPEstat call throwing) should never fail the whole investigation
  }
}

function mergeReports(a, b) {
  const seen = new Set();
  const out = [];
  for (const r of [...(a ?? []), ...(b ?? [])]) {
    if (!r || seen.has(r.id)) continue;
    seen.add(r.id);
    out.push(r);
  }
  return out;
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
          // The dossier's own name-indexed report search (entityCorrelation.js,
          // via crossReference.js#findAiReportsByEntityName) fills the gap
          // crossReferenceIndicator's IOC-VALUE-keyed matchingAiReports can
          // never fill for a bare group/entity name -- merged in (deduped by
          // id) rather than replacing crossRef's own IOC-based hits, so a
          // ransomwareGroup search keeps both signals.
          matchingAiReports: mergeReports(crossRef.matchingAiReports, moduleData.dossier?.threatReports),
          relatedIocs: crossRef.relatedIocs,
        }
      : type === "name"
        ? {
            matchedMalwareFamilies: (moduleData.malware ?? []).map((m) => m.entity.name),
            associatedThreatActors: (moduleData.actors ?? []).map((a) => a.name),
            activeCampaigns: (moduleData.campaigns ?? []).map((c) => c.name),
            matchingAiReports: moduleData.dossier?.threatReports ?? [],
            relatedIocs: [],
          }
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
    // Genuinely sequential (like ransomwareGroup/name below) -- the graph
    // needs to know which malware family VirusTotal/Hybrid Analysis just
    // classified this hash as (moduleData.malwareFamily), so it can pivot
    // into that family's full tracked profile instead of only checking
    // whether this EXACT hash string already sits in an entity's own iocs
    // list (see investigationGraph.js#gatherCrossReferenceOnly).
    const data = await hashModule.gather(normalized, type);
    const graph = await computeGraphResult(type, normalized, data);
    return assemble(normalized, type, data, crossReferenceIndicator(normalized), graph);
  }
  if (type === "ransomwareGroup") {
    // Genuinely sequential (like "name" below) -- the graph target now reads
    // moduleData.dossier.primaryEntity (entityCorrelation.js), so the graph
    // fetch must wait for the module's own dossier-building gather() to
    // finish rather than racing it with an empty moduleData stand-in.
    const data = await ransomwareGroupModule.gather(normalized);
    const graph = await computeGraphResult("ransomwareGroup", normalized, data);
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
