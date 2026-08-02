// Intelligence Investigation Console orchestrator -- detects the indicator
// type, routes to the matching per-type module, runs the shared cross-
// reference pass, and assembles the Universal Overview every indicator type
// shows regardless of what kind it is. This is the only place that knows
// about all 16 types; every module below it only knows its own shape.
import { detectIndicatorType, isHashType, isIpType } from "./detect.js";
import * as ipModule from "./ipModule.js";
import * as domainModule from "./domainModule.js";
import * as urlModule from "./urlModule.js";
import * as hashModule from "./hashModule.js";
import * as cveModule from "./cveModule.js";
import * as entityModule from "./entityModule.js";
import * as artifactModule from "./artifactModule.js";
import { crossReferenceIndicator } from "./crossReference.js";

const ARTIFACT_TYPES = new Set(["email", "fileName", "processName", "registryKey", "userAgent"]);

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

function assemble(indicator, type, moduleData, crossRef) {
  const verdict = moduleData.verdict;
  const { firstSeen, lastSeen } = firstLastSeenFor(type, moduleData);

  const overview = {
    indicator,
    indicatorType: type,
    overallVerdict: verdict?.verdict ?? "unknown",
    verdictLabel: verdict?.label ?? "No Data",
    confidence: verdict?.confidence ?? "Low",
    severity: verdict?.severity ?? "UNKNOWN",
    riskLevel: verdict?.riskLevel ?? "Low",
    recommendedPriority: verdict?.priority ?? "Low",
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
  };
}

/** @returns {Promise<import("../../src/types/threat-intel.js").InvestigationResult>} */
export async function investigate(rawValue) {
  const { type, normalized } = detectIndicatorType(rawValue);

  if (type === "cve") {
    const data = await cveModule.gather(normalized);
    return assemble(normalized, "cve", data, null);
  }
  if (isIpType(type)) {
    const data = await ipModule.gather(normalized);
    return assemble(normalized, "ip", data, crossReferenceIndicator(normalized));
  }
  if (type === "domain") {
    const data = await domainModule.gather(normalized);
    return assemble(normalized, "domain", data, crossReferenceIndicator(normalized));
  }
  if (type === "url") {
    const data = await urlModule.gather(normalized);
    return assemble(normalized, "url", data, crossReferenceIndicator(normalized));
  }
  if (isHashType(type)) {
    const data = await hashModule.gather(normalized, type);
    return assemble(normalized, type, data, crossReferenceIndicator(normalized));
  }
  if (type === "name") {
    const data = await entityModule.gather(normalized);
    return assemble(normalized, "name", data, null);
  }
  // email / fileName / processName / registryKey / userAgent -- cross-reference-only
  const data = await artifactModule.gather(normalized, type);
  return assemble(normalized, type, data, data.crossReference);
}

export { detectIndicatorType };
