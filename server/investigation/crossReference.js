// Shared cross-reference pass -- for any indicator value, checks whether it
// already appears in this app's own previously-ingested intelligence
// (Malware/Threat Actor/Campaign Intelligence entity stores, AI Summarization
// reports' extracted IOCs). This is what powers "Active Campaigns" /
// "Associated Threat Actor(s)" / "Related Intelligence" for every indicator
// type -- one implementation, shared by every per-type module, instead of
// each module re-deriving its own version. No IP/domain/hash -> actor/
// campaign correlation existed anywhere in this app before this file; the
// only precedent was TriageConsole.tsx's single-hop `linkedFamily` match
// against malware iocs, which this generalizes into a full pass across all
// three entity stores plus AI report IOCs.
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "../threatActorIntelligence.js";
import { getAllEntities as getCampaignEntities } from "../campaignIntelligence.js";
import { getAllReports as getAiReports } from "../aiThreatSummaryStore.js";

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

/** Flattens an AiThreatSummaryIocs object into one lowercase Set for cheap membership checks. */
function aiReportIocSet(iocs) {
  const set = new Set();
  for (const key of ["ipAddresses", "domains", "urls", "hashes", "emailAddresses", "registryKeys", "fileNames", "userAgents"]) {
    for (const v of iocs?.[key] ?? []) set.add(norm(v));
  }
  return set;
}

/**
 * @param {string} value - the raw indicator (already normalized by detect.js)
 * @returns {{
 *   matchedMalwareFamilies: string[],
 *   associatedThreatActors: string[],
 *   activeCampaigns: string[],
 *   matchingAiReports: Array<{id:string, articleTitle:string, articleLink:string, articleSource:string, publishedDate:string}>,
 *   relatedIocs: Array<{indicator:string, indicatorType:string, malwareFamily:string}>,
 *   siblingIndicators: Array<{indicator:string, indicatorType:string, malwareFamily:string}>,
 * }}
 */
export function crossReferenceIndicator(value) {
  const target = norm(value);
  const malwareEntities = getMalwareEntities();
  const actorEntities = getActorEntities();
  const campaignEntities = getCampaignEntities();
  const aiReports = getAiReports();

  const matchedFamilies = new Set();
  const relatedIocs = [];
  // "Related Indicators" (see server/investigation/ipModule.js) -- once this
  // value matches a malware family, that family's OTHER indicators are
  // genuinely "other indicators tied to the same campaign/actor" (campaign/
  // actor are themselves derived from the family, same chain
  // server/investigation/pivotChain.js already uses). Deduped by value since
  // the same indicator can appear in both `iocs` and `articleIocs`.
  const siblingIndicators = [];
  const seenSiblings = new Set([target]);
  for (const entity of malwareEntities) {
    const allIocs = [...(entity.iocs ?? []), ...(entity.articleIocs ?? [])];
    const hit = allIocs.find((ioc) => norm(ioc.indicator) === target);
    if (hit) {
      matchedFamilies.add(entity.name);
      relatedIocs.push({ indicator: hit.indicator, indicatorType: hit.indicatorType, malwareFamily: entity.name, firstSeen: hit.firstSeen ?? null });
      for (const sibling of allIocs) {
        const key = norm(sibling.indicator);
        if (seenSiblings.has(key) || siblingIndicators.length >= 20) continue;
        seenSiblings.add(key);
        siblingIndicators.push({ indicator: sibling.indicator, indicatorType: sibling.indicatorType, malwareFamily: entity.name });
      }
    }
  }

  const matchingAiReports = aiReports.filter((r) => aiReportIocSet(r.iocs).has(target)).slice(0, 10);
  for (const report of matchingAiReports) {
    for (const m of report.malware ?? []) matchedFamilies.add(m.family);
  }

  const familyList = Array.from(matchedFamilies);
  const familyListLower = familyList.map(norm);

  const associatedThreatActors = new Set();
  for (const actor of actorEntities) {
    if ((actor.malwareUsed ?? []).some((m) => familyListLower.includes(norm(m)))) associatedThreatActors.add(actor.name);
  }
  for (const report of matchingAiReports) {
    for (const a of report.threatActors ?? []) associatedThreatActors.add(a.group);
  }

  const activeCampaigns = new Set();
  for (const campaign of campaignEntities) {
    if ((campaign.associatedMalware ?? []).some((m) => familyListLower.includes(norm(m)))) activeCampaigns.add(campaign.name);
  }

  return {
    matchedMalwareFamilies: familyList,
    associatedThreatActors: Array.from(associatedThreatActors),
    activeCampaigns: Array.from(activeCampaigns),
    matchingAiReports: matchingAiReports.map((r) => ({
      id: r.id,
      articleTitle: r.articleTitle,
      articleLink: r.articleLink,
      articleSource: r.articleSource,
      publishedDate: r.publishedDate,
    })),
    relatedIocs: relatedIocs.slice(0, 20),
    siblingIndicators,
  };
}

/** Name-search variant for malware/actor/campaign-name indicators -- reused by entityModule.js and artifactModule.js's fallback search. */
export function searchEntitiesByName(query) {
  const q = norm(query);
  const matches = (name, aliases) => norm(name).includes(q) || (aliases ?? []).some((a) => norm(a).includes(q));
  return {
    malware: getMalwareEntities().filter((e) => matches(e.name, e.aliases)),
    actors: getActorEntities().filter((e) => matches(e.name, e.aliases)),
    campaigns: getCampaignEntities().filter((e) => matches(e.name, e.aliases)),
  };
}
