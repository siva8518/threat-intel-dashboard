// Pivot Chain -- lets an analyst walk Threat Actor -> Campaign -> Malware ->
// CVE -> Victim -> IP -> Domain -> Report, one hop at a time, starting from
// any node. Every edge below is backed by a field this app already computes
// somewhere (see the entity stores, cveProfile.js, crossReference.js) -- no
// new correlation logic is invented here, this module just reads the right
// existing store for whichever node type is centered and reverse-scans a
// neighboring store when the forward field doesn't exist (e.g. malware has
// no back-reference to the actors that use it, so actor lookups are
// reverse-matched against `actor.malwareUsed`).
//
// A hop that this app has NO real data source for at all (Malware -> CVE,
// Victim -> IP/Domain, IP/Domain -> CVE, IP/Domain -> Victim, CVE -> Victim,
// Report -> Victim) is listed in `unavailableHops` with a plain-language
// reason, distinct from a hop that's simply empty for this particular
// entity -- the UI must render these differently (an honest "no data source
// links these" message, never a silent empty section) per this app's
// established "never fabricate" rule.
import { getAllEntities as getActorEntities } from "../threatActorIntelligence.js";
import { getAllEntities as getCampaignEntities } from "../campaignIntelligence.js";
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getDarkWebEntities } from "../darkWebIntelligence.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { getAllReports as getAiReports, getReportById } from "../aiThreatSummaryStore.js";
import { buildCveProfile } from "../cveProfile.js";
import { getAllGithubRepos } from "../githubIntel/index.js";
import { crossReferenceIndicator } from "./crossReference.js";
import { resolveDnsRecords, reverseDns } from "../lib/dnsRecords.js";
import { getPassiveDns } from "../connectors/otx.js";
import * as cache from "../cache.js";

export const PIVOT_NODE_TYPES = ["actor", "campaign", "malware", "cve", "victim", "ip", "domain", "report"];

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

function edge(id, label, linkBasis) {
  return { id, label, linkBasis };
}

function emptyNeighbors() {
  return { actor: [], campaign: [], malware: [], cve: [], victim: [], ip: [], domain: [], report: [] };
}

function findByNameOrAlias(entities, key) {
  const target = norm(key);
  return entities.find((e) => norm(e.name) === target || (e.aliases ?? []).some((a) => norm(a) === target)) ?? null;
}

function dedupeEdges(edges) {
  const seen = new Set();
  const out = [];
  for (const e of edges) {
    const k = norm(e.id);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(e);
  }
  return out;
}

// --- Actor ---------------------------------------------------------------

function actorNeighbors(entity) {
  const neighbors = emptyNeighbors();
  if (!entity) return neighbors;

  neighbors.malware = entity.malwareUsed.map((name) => edge(name, name, "Direct: actor.malwareUsed"));
  neighbors.cve = entity.cveExploited.map((id) => edge(id, id, "Direct: actor.cveExploited"));

  const names = new Set([norm(entity.name), ...entity.aliases.map(norm)]);
  neighbors.campaign = getCampaignEntities()
    .filter((c) => (c.associatedActors ?? []).some((a) => names.has(norm(a))))
    .map((c) => edge(c.name, c.name, "Reverse: campaign.associatedActors"));

  const ransomwareEdges = getRansomwareCampaigns()
    .filter((r) => names.has(norm(r.group)))
    .map((r) => edge(r.victim, r.victim, "Reverse: ransomware disclosure group match"));
  const darkWebEdges = getDarkWebEntities()
    .filter((d) => (d.associatedActors ?? []).some((a) => names.has(norm(a))))
    .map((d) => edge(d.victimOrg ?? d.name, d.victimOrg ?? d.name, "Reverse: dark-web finding associatedActors"));
  neighbors.victim = dedupeEdges([...ransomwareEdges, ...darkWebEdges]);

  return neighbors;
}

async function gatherActor(key) {
  const entity = findByNameOrAlias(getActorEntities(), key);
  return {
    node: { type: "actor", id: entity?.id ?? key, label: entity?.name ?? key, summary: entity?.description ?? null, found: Boolean(entity) },
    neighbors: actorNeighbors(entity),
    unavailableHops: [],
  };
}

// --- Campaign --------------------------------------------------------------

function campaignNeighbors(entity) {
  const neighbors = emptyNeighbors();
  if (!entity) return neighbors;

  neighbors.actor = entity.associatedActors.map((name) => edge(name, name, "Direct: campaign.associatedActors"));
  neighbors.malware = entity.associatedMalware.map((name) => edge(name, name, "Direct: campaign.associatedMalware"));
  neighbors.cve = entity.cveExploited.map((id) => edge(id, id, "Direct: campaign.cveExploited"));

  const actorNames = new Set(entity.associatedActors.map(norm));
  const ransomwareEdges = getRansomwareCampaigns()
    .filter((r) => actorNames.has(norm(r.group)))
    .map((r) => edge(r.victim, r.victim, "Indirect: via a shared actor in campaign.associatedActors"));
  const darkWebEdges = getDarkWebEntities()
    .filter((d) => (d.associatedActors ?? []).some((a) => actorNames.has(norm(a))) || (d.associatedMalware ?? []).some((m) => entity.associatedMalware.map(norm).includes(norm(m))))
    .map((d) => edge(d.victimOrg ?? d.name, d.victimOrg ?? d.name, "Indirect: via a shared actor or malware family"));
  neighbors.victim = dedupeEdges([...ransomwareEdges, ...darkWebEdges]);

  return neighbors;
}

async function gatherCampaign(key) {
  const entity = findByNameOrAlias(getCampaignEntities(), key);
  return {
    node: { type: "campaign", id: entity?.id ?? key, label: entity?.name ?? key, summary: entity?.description ?? null, found: Boolean(entity) },
    neighbors: campaignNeighbors(entity),
    unavailableHops: [],
  };
}

// --- Malware ---------------------------------------------------------------

function malwareNeighbors(entity) {
  const neighbors = emptyNeighbors();
  if (!entity) return neighbors;

  const allIocs = [...(entity.iocs ?? []), ...(entity.articleIocs ?? [])];
  const ipEdges = [];
  const domainEdges = [];
  for (const ioc of allIocs) {
    if (ioc.indicatorType === "ip") ipEdges.push(edge(ioc.indicator, ioc.indicator, "Direct: malware.iocs / articleIocs"));
    else if (ioc.indicatorType === "domain") domainEdges.push(edge(ioc.indicator, ioc.indicator, "Direct: malware.iocs / articleIocs"));
    else if (ioc.indicatorType === "url") {
      try {
        const host = new URL(ioc.indicator).hostname;
        domainEdges.push(edge(host, host, "Direct: hostname extracted from malware.iocs / articleIocs URL"));
      } catch {
        // malformed URL indicator -- skip rather than guess
      }
    }
  }
  neighbors.ip = dedupeEdges(ipEdges);
  neighbors.domain = dedupeEdges(domainEdges);

  const names = new Set([norm(entity.name), ...entity.aliases.map(norm)]);
  neighbors.actor = getActorEntities()
    .filter((a) => (a.malwareUsed ?? []).some((m) => names.has(norm(m))))
    .map((a) => edge(a.name, a.name, "Reverse: actor.malwareUsed"));
  neighbors.campaign = getCampaignEntities()
    .filter((c) => (c.associatedMalware ?? []).some((m) => names.has(norm(m))))
    .map((c) => edge(c.name, c.name, "Reverse: campaign.associatedMalware"));

  return neighbors;
}

async function gatherMalware(key) {
  const entity = findByNameOrAlias(getMalwareEntities(), key);
  return {
    node: { type: "malware", id: entity?.id ?? key, label: entity?.name ?? key, summary: entity?.description ?? null, found: Boolean(entity) },
    neighbors: malwareNeighbors(entity),
    unavailableHops: [{ neighborType: "cve", reason: "Malware entities in this app carry no CVE field -- no source links a malware family directly to a CVE." }],
  };
}

// --- CVE ---------------------------------------------------------------

async function gatherCve(key) {
  const cveId = key.trim().toUpperCase();
  const profile = buildCveProfile(cveId, {
    attackData: cache.getEntry("attack").data,
    newsItems: cache.getEntry("news").data?.items ?? [],
    githubRepos: getAllGithubRepos(),
    exploitIndex: cache.getEntry("exploitdb").data?.cveIndex,
  });

  const neighbors = emptyNeighbors();
  neighbors.actor = profile.relatedActors.map((a) => edge(a.name, a.name, "Reverse: ATT&CK citation (group.cveIds / citing campaign / citing software)"));
  neighbors.malware = profile.relatedMalware.map((name) => edge(name, name, "Reverse: ATT&CK citation (software.cveIds)"));
  neighbors.campaign = profile.relatedCampaigns.map((c) => edge(c.name, c.name, "Reverse: ATT&CK citation (campaign.cveIds)"));
  for (const ioc of profile.relatedIocs) {
    const bucket = ioc.indicatorType === "ip" ? "ip" : ioc.indicatorType === "domain" ? "domain" : null;
    if (bucket) neighbors[bucket].push(edge(ioc.indicator, ioc.indicator, "Indirect: via a shared malware family (one hop, not a direct CVE-IOC tag)"));
  }
  neighbors.ip = dedupeEdges(neighbors.ip);
  neighbors.domain = dedupeEdges(neighbors.domain);
  neighbors.report = getAiReports()
    .filter((r) => (r.cves ?? []).some((c) => norm(c.id) === norm(cveId)))
    .map((r) => edge(r.id, r.articleTitle, "Direct: report.cves"));

  return {
    node: { type: "cve", id: cveId, label: cveId, summary: null, found: profile.relatedActors.length + profile.relatedMalware.length + profile.relatedCampaigns.length + neighbors.report.length > 0 },
    neighbors,
    unavailableHops: [{ neighborType: "victim", reason: "No CVE-to-victim linkage exists anywhere in this app's data model." }],
  };
}

// --- Victim ---------------------------------------------------------------

async function gatherVictim(key) {
  const target = norm(key);
  const ransomwareHits = getRansomwareCampaigns().filter((r) => norm(r.victim) === target);
  const darkWebHits = getDarkWebEntities().filter((d) => norm(d.victimOrg) === target || norm(d.name) === target);
  const found = ransomwareHits.length > 0 || darkWebHits.length > 0;

  const neighbors = emptyNeighbors();
  neighbors.actor = dedupeEdges([
    ...ransomwareHits.map((r) => edge(r.group, r.group, "Direct: ransomware disclosure record")),
    ...darkWebHits.flatMap((d) => (d.associatedActors ?? []).map((a) => edge(a, a, "Direct: dark-web finding associatedActors"))),
  ]);
  neighbors.malware = dedupeEdges(darkWebHits.flatMap((d) => (d.associatedMalware ?? []).map((m) => edge(m, m, "Direct: dark-web finding associatedMalware"))));
  neighbors.cve = dedupeEdges(darkWebHits.flatMap((d) => (d.cveExploited ?? []).map((id) => edge(id, id, "Direct: dark-web finding cveExploited"))));

  const summaryParts = [];
  const sector = ransomwareHits.find((r) => r.sector && r.sector !== "Unknown")?.sector;
  const country = ransomwareHits.find((r) => r.country && r.country !== "Unknown")?.country;
  if (sector) summaryParts.push(sector);
  if (country) summaryParts.push(country);
  const dwType = darkWebHits.find((d) => d.type)?.type;
  if (dwType) summaryParts.push(dwType);

  return {
    node: { type: "victim", id: key, label: key, summary: summaryParts.length ? summaryParts.join(" • ") : null, found },
    neighbors,
    unavailableHops: [
      { neighborType: "ip", reason: "No indicator-level data links this victim to specific IP infrastructure." },
      { neighborType: "domain", reason: "No indicator-level data links this victim to specific domain infrastructure." },
    ],
  };
}

// --- IP / Domain ---------------------------------------------------------------

async function ipDomainNeighbors(type, value) {
  const crossRef = crossReferenceIndicator(value);
  const neighbors = emptyNeighbors();
  neighbors.malware = crossRef.matchedMalwareFamilies.map((name) => edge(name, name, "Cross-reference: shared indicator in malware.iocs / articleIocs"));
  neighbors.actor = crossRef.associatedThreatActors.map((name) => edge(name, name, "Cross-reference: actor.malwareUsed includes matched family"));
  neighbors.campaign = crossRef.activeCampaigns.map((name) => edge(name, name, "Cross-reference: campaign.associatedMalware includes matched family"));
  neighbors.report = crossRef.matchingAiReports.map((r) => edge(r.id, r.articleTitle, "Direct: indicator present in report.iocs"));

  try {
    if (type === "ip") {
      const [hostname, passive] = await Promise.allSettled([reverseDns(value), getPassiveDns("ip", value)]);
      const edges = [];
      if (hostname.status === "fulfilled" && hostname.value) edges.push(edge(hostname.value, hostname.value, "Live: reverse DNS (PTR)"));
      if (passive.status === "fulfilled") for (const rec of passive.value) if (rec.hostname) edges.push(edge(rec.hostname, rec.hostname, "Live: OTX passive DNS"));
      neighbors.domain = dedupeEdges(edges);
    } else {
      const [records, passive] = await Promise.allSettled([resolveDnsRecords(value), getPassiveDns("domain", value)]);
      const edges = [];
      if (records.status === "fulfilled") for (const ip of [...records.value.a, ...records.value.aaaa]) edges.push(edge(ip, ip, "Live: DNS A/AAAA record"));
      if (passive.status === "fulfilled") {
        // OTX passive DNS mixes A/AAAA records (where `address` is a real IP)
        // with CNAME records (where `address` is another hostname) -- only
        // the former belongs in the IP bucket, otherwise a hostname would be
        // mislabeled as an IP address.
        for (const rec of passive.value) if (rec.address && (rec.recordType === "A" || rec.recordType === "AAAA")) edges.push(edge(rec.address, rec.address, "Live: OTX passive DNS"));
      }
      neighbors.ip = dedupeEdges(edges);
    }
  } catch {
    // live DNS/passive-DNS lookup failed entirely -- leave that side empty rather than guess
  }

  return neighbors;
}

async function gatherIpOrDomain(type, key) {
  const value = key.trim();
  const neighbors = await ipDomainNeighbors(type, value);
  const cveReason = "No direct indicator-to-CVE linkage exists in this app's data model (the only related path -- via a shared malware family -- is CVE-centric, not indicator-centric, and isn't surfaced here to avoid a misleading direct-looking link).";
  const victimReason = `No data source links specific ${type === "ip" ? "IP" : "domain"} infrastructure to a named victim.`;
  return {
    node: { type, id: value, label: value, summary: null, found: true },
    neighbors,
    unavailableHops: [
      { neighborType: "cve", reason: cveReason },
      { neighborType: "victim", reason: victimReason },
    ],
  };
}

// --- Report ---------------------------------------------------------------

async function gatherReport(key) {
  const report = getReportById(key);
  if (!report) {
    return { node: { type: "report", id: key, label: key, summary: null, found: false }, neighbors: emptyNeighbors(), unavailableHops: [{ neighborType: "victim", reason: "AI Summarization reports carry no victim-organization field." }] };
  }

  const neighbors = emptyNeighbors();
  neighbors.cve = (report.cves ?? []).map((c) => edge(c.id, c.id, "Direct: report.cves"));
  neighbors.ip = (report.iocs?.ipAddresses ?? []).map((v) => edge(v, v, "Direct: report.iocs.ipAddresses"));
  neighbors.domain = (report.iocs?.domains ?? []).map((v) => edge(v, v, "Direct: report.iocs.domains"));

  const actorEntities = getActorEntities();
  neighbors.actor = (report.threatActors ?? []).map((a) => {
    const match = findByNameOrAlias(actorEntities, a.group);
    return edge(match?.name ?? a.group, a.group, match ? "Direct: report.threatActors (matched to canonical actor entity)" : "Report-only: no canonical actor entity matches this name yet");
  });

  const malwareEntities = getMalwareEntities();
  neighbors.malware = (report.malware ?? []).map((m) => {
    const match = findByNameOrAlias(malwareEntities, m.family);
    return edge(match?.name ?? m.family, m.family, match ? "Direct: report.malware (matched to canonical malware entity)" : "Report-only: no canonical malware entity matches this name yet");
  });

  if (report.campaignName) {
    const match = findByNameOrAlias(getCampaignEntities(), report.campaignName);
    neighbors.campaign = [edge(match?.name ?? report.campaignName, report.campaignName, match ? "Direct: report.campaignName (matched to canonical campaign entity)" : "Report-only: no canonical campaign entity matches this name yet")];
  }

  return {
    node: { type: "report", id: report.id, label: report.articleTitle, summary: `${report.articleSource} • ${report.publishedDate}`, found: true },
    neighbors,
    unavailableHops: [{ neighborType: "victim", reason: "AI Summarization reports carry no victim-organization field." }],
  };
}

// --- Orchestrator ---------------------------------------------------------------

export async function getPivotNeighbors(nodeType, key) {
  if (!PIVOT_NODE_TYPES.includes(nodeType)) throw new Error(`Unknown pivot node type "${nodeType}"`);
  if (!key || !key.trim()) throw new Error("key is required");

  switch (nodeType) {
    case "actor":
      return gatherActor(key);
    case "campaign":
      return gatherCampaign(key);
    case "malware":
      return gatherMalware(key);
    case "cve":
      return gatherCve(key);
    case "victim":
      return gatherVictim(key);
    case "ip":
      return gatherIpOrDomain("ip", key);
    case "domain":
      return gatherIpOrDomain("domain", key);
    case "report":
      return gatherReport(key);
    default:
      throw new Error(`Unknown pivot node type "${nodeType}"`);
  }
}
