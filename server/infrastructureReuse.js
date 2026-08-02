// "Infrastructure Reuse" for an AI Summarization report -- hunters don't
// investigate one IOC in isolation, they care whether THIS report's
// indicators already showed up somewhere else this platform tracks (a
// different malware family, a different actor, a different campaign, or a
// different AI Summarization report entirely). Built entirely on real,
// already-correlatable data -- reuses server/investigation/crossReference.js's
// crossReferenceIndicator() (the same cross-reference the Intelligence
// Investigation Console uses for a single pasted indicator) per-IOC, so this
// needed zero new correlation logic, only aggregation.
//
// Computed fresh at serve time (see server/routes/dashboard.js), never
// persisted into the stored report JSON -- the entity stores it reads
// against keep growing as new articles are processed, so a reuse hit
// discovered next week for an old report should show up the next time that
// report is *viewed*, not only if it happened to exist at generation time.
import { crossReferenceIndicator } from "./investigation/crossReference.js";

const IOC_CATEGORY_TO_TYPE = {
  ipAddresses: "ip",
  domains: "domain",
  urls: "url",
  hashes: "hash",
};

function flattenIndicators(iocs) {
  const out = [];
  for (const [category, type] of Object.entries(IOC_CATEGORY_TO_TYPE)) {
    for (const value of iocs?.[category] ?? []) out.push({ indicator: value, indicatorType: type });
  }
  return out;
}

/**
 * @param {import("./aiThreatSummaryStore.js").AiThreatSummaryReport} report
 * @returns {{
 *   hasReuse: boolean,
 *   threatActors: string[],
 *   relatedMalwareFamilies: string[],
 *   relatedCampaigns: string[],
 *   matchedIndicators: Array<{indicator:string, indicatorType:string, linkedMalwareFamilies:string[], linkedThreatActors:string[], linkedCampaigns:string[], seenInOtherReports:Array<{title:string,link:string,publishedDate:string}>}>,
 *   timeline: Array<{date:string, label:string, link:string|null}>,
 * }}
 */
export function buildInfrastructureReuse(report) {
  const threatActors = new Set();
  const relatedMalwareFamilies = new Set();
  const relatedCampaigns = new Set();
  const matchedIndicators = [];
  const relatedReports = new Map(); // dedupe by report id

  for (const { indicator, indicatorType } of flattenIndicators(report.iocs)) {
    const xref = crossReferenceIndicator(indicator);
    // Excludes this report's own IOC set matching itself -- every indicator
    // trivially "matches" the report it came from, which isn't reuse.
    const otherReports = xref.matchingAiReports.filter((r) => r.id !== report.id);
    const hasHit = xref.matchedMalwareFamilies.length > 0 || xref.associatedThreatActors.length > 0 || xref.activeCampaigns.length > 0 || otherReports.length > 0;
    if (!hasHit) continue;

    for (const f of xref.matchedMalwareFamilies) relatedMalwareFamilies.add(f);
    for (const a of xref.associatedThreatActors) threatActors.add(a);
    for (const c of xref.activeCampaigns) relatedCampaigns.add(c);
    for (const r of otherReports) relatedReports.set(r.id, r);

    matchedIndicators.push({
      indicator,
      indicatorType,
      linkedMalwareFamilies: xref.matchedMalwareFamilies,
      linkedThreatActors: xref.associatedThreatActors,
      linkedCampaigns: xref.activeCampaigns,
      seenInOtherReports: otherReports.map((r) => ({ title: r.articleTitle, link: r.articleLink, publishedDate: r.publishedDate })),
    });
  }

  // Real, verifiable timeline -- this report's own publish date plus every
  // other AI Summarization report that shares one of its indicators, sorted
  // chronologically. Deliberately no "Victims" row: this platform has no
  // per-victim linkage for malware/actor IOCs (DarkWebIntelligenceEntity
  // tracks victimOrg for a different kind of finding entirely), so rather
  // than invent one, it's simply not included.
  const timeline = [
    { date: report.publishedDate, label: report.articleTitle, link: report.articleLink },
    ...[...relatedReports.values()].map((r) => ({ date: r.publishedDate, label: r.articleTitle, link: r.articleLink })),
  ].sort((a, b) => new Date(a.date) - new Date(b.date));

  return {
    hasReuse: matchedIndicators.length > 0,
    threatActors: [...threatActors],
    relatedMalwareFamilies: [...relatedMalwareFamilies],
    relatedCampaigns: [...relatedCampaigns],
    matchedIndicators,
    timeline: matchedIndicators.length > 0 ? timeline : [],
  };
}
