// Turns the platform's own already-synced/correlated data into small,
// retrievable text chunks -- this is the entire "knowledge base" the chatbot
// can ever answer from. No new data is fetched here: every source below is
// something server/connectors/ already syncs into server/cache.js, so the
// chatbot's knowledge is always exactly what the rest of the dashboard shows,
// nothing more.
import * as cache from "../cache.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { correlateCves } from "../correlate.js";
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "../threatActorIntelligence.js";
import { getAllEntities as getCampaignEntities } from "../campaignIntelligence.js";
import { MAX_CHUNKS_PER_SOURCE as CAP } from "./config.js";

function cveChunks() {
  const nvd = cache.getEntry("nvd").data;
  if (!nvd) return [];
  const kevEntries = cache.getEntry("cisa-kev").data?.entries ?? [];
  const epssScores = cache.getEntry("epss").data ?? {};
  const records = correlateCves(nvd.latestCves.records.slice(0, CAP.cve), kevEntries, epssScores);

  return records.map((c) => ({
    id: `cve:${c.id}`,
    text:
      `${c.id} (${c.severity}${c.cvssScore ? `, CVSS ${c.cvssScore}` : ""}): ${c.description} ` +
      `Affects ${c.vendor} ${c.product}. Published ${c.publishedDate.slice(0, 10)}. ` +
      `${c.knownExploited ? "Confirmed actively exploited (CISA KEV)." : ""} ` +
      `${c.epssScore !== null ? `EPSS exploit-probability score: ${Math.round(c.epssScore * 100)}%.` : ""}`,
    metadata: { type: "cve", label: c.id, url: c.sourceUrl, date: c.publishedDate },
  }));
}

function kevChunks() {
  const entries = (cache.getEntry("cisa-kev").data?.entries ?? []).slice(0, CAP.kev);
  return entries.map((e) => ({
    id: `kev:${e.cveId}`,
    text:
      `${e.cveId} was added to CISA's Known Exploited Vulnerabilities (KEV) catalog on ${e.dateAdded}. ` +
      `"${e.vulnerabilityName}" affecting ${e.vendorProject} ${e.product}. Required action: ${e.requiredAction} ` +
      `Due date: ${e.dueDate}. ${e.ransomwareUse ? "Known to be used in ransomware campaigns." : ""}`,
    metadata: { type: "kev", label: `${e.cveId} (KEV)`, url: `https://nvd.nist.gov/vuln/detail/${e.cveId}`, date: e.dateAdded },
  }));
}

function ransomwareChunks() {
  const campaigns = getRansomwareCampaigns().slice(0, CAP.ransomware);
  return campaigns.map((c) => ({
    id: `ransomware:${c.id}`,
    text: `Ransomware group "${c.group}" listed victim "${c.victim}" (sector: ${c.sector}, country: ${c.country}) on ${c.discoveredDate?.slice(0, 10)}.`,
    metadata: { type: "ransomware", label: `${c.group} vs. ${c.victim}`, url: c.sourceUrl, date: c.discoveredDate },
  }));
}

// Sourced from server/threatActorIntelligence.js -- the canonical, deduped
// "one record per actor" store built by automatically extracting names from
// news article text (server/threatActorExtraction.js) and enriching/merging
// against MITRE ATT&CK's Groups list, ransomware tracker data, and
// server/malwareIntelligence.js's own entities (for malware<->actor
// co-mentions). reconcile() seeds one entity per ATT&CK group up front, so
// this is a strict superset of the old plain-ATT&CK actor chunks it replaces
// -- nothing regresses, and a brand-new group named in a vendor blog before
// it ever reaches ATT&CK still gets a real, citable chunk the same way
// malwareChunks() fixed this for malware families.
function actorChunks() {
  const attackIndex = cache.getEntry("attack").data?.techniques ?? [];
  const techniqueById = new Map(attackIndex.map((t) => [t.id, t]));
  const entities = getActorEntities().slice(0, CAP.actors);

  return entities.map((a) => {
    const techniqueNames = a.techniqueIds
      .map((id) => techniqueById.get(id))
      .filter(Boolean)
      .slice(0, 10)
      .map((t) => `${t.name} (${t.id})`)
      .join(", ");
    const recentArticles = a.articles.slice(0, 5).map((n) => `"${n.title}" (${n.source}, ${n.publishedDate?.slice(0, 10)})`).join("; ");

    return {
      id: `actor:${a.id}`,
      text:
        `Threat actor "${a.name}"${a.aliases.length ? ` (aliases: ${a.aliases.join(", ")})` : ""}, type: ${a.type}` +
        `${a.verified ? " -- confirmed" : " -- reported in news coverage, not yet confirmed via MITRE ATT&CK or a ransomware tracker"}. ` +
        `${a.description ? `${a.description} ` : ""}` +
        `${a.country ? `Believed origin: ${a.country}. ` : ""}` +
        `${a.motivations.length ? `Motivation: ${a.motivations.join(", ")}. ` : ""}` +
        `${a.activeSince ? `Active since ${a.activeSince}. ` : ""}` +
        `${a.malwareUsed.length ? `Uses malware/tools: ${a.malwareUsed.join(", ")}. ` : ""}` +
        `${a.targetedIndustries.length ? `Targets industries: ${a.targetedIndustries.join(", ")}. ` : ""}` +
        `${a.targetedCountries.length ? `Targets countries: ${a.targetedCountries.join(", ")}. ` : ""}` +
        `${a.cveExploited.length ? `Exploits: ${a.cveExploited.join(", ")}. ` : ""}` +
        `${techniqueNames ? `Uses techniques: ${techniqueNames}. ` : ""}` +
        `${recentArticles ? `Recent coverage: ${recentArticles}.` : ""}`,
      metadata: { type: "actor", label: a.name, url: a.attackUrl, date: a.lastSeen },
    };
  });
}

function techniqueChunks() {
  const techniques = (cache.getEntry("attack").data?.techniques ?? []).slice(0, CAP.techniques);
  return techniques.map((t) => ({
    id: `technique:${t.id}`,
    text: `MITRE ATT&CK technique ${t.id}: "${t.name}", tactic: ${t.tactic}.`,
    metadata: { type: "technique", label: `${t.id} ${t.name}`, url: t.url, date: null },
  }));
}

// Sourced from server/malwareIntelligence.js -- the canonical, deduped "one
// record per family" store built by automatically extracting names from news
// article text (server/malwareExtraction.js) and enriching/merging against
// MITRE ATT&CK's Software list and the live IOC feed (server/malwareIntelligence.js#reconcile).
// This is what actually fixed "the chatbot can't answer 'What is Bumblebee?'"
// -- unlike the old IOC-frequency-only view, a family with real news
// coverage but modest current IOC volume still gets a real, citable chunk.
function malwareChunks() {
  const entities = getMalwareEntities().slice(0, CAP.malware);
  return entities.map((m) => {
    const recentArticles = m.articles.slice(0, 5).map((a) => `"${a.title}" (${a.source}, ${a.publishedDate?.slice(0, 10)})`).join("; ");
    return {
      id: `malware:${m.id}`,
      text:
        `Malware family "${m.name}"${m.aliases.length ? ` (aliases: ${m.aliases.join(", ")})` : ""}` +
        `${m.verified ? " -- confirmed" : " -- reported in news coverage, not yet confirmed via MITRE ATT&CK or a live indicator feed"}. ` +
        `${m.description ? `${m.description} ` : ""}` +
        `${m.iocSightings ? `Currently has ${m.iocSightings} live indicator sighting(s). ` : ""}` +
        `${recentArticles ? `Recent coverage: ${recentArticles}.` : ""}`,
      metadata: { type: "malware", label: m.name, url: m.attackUrl, date: m.lastSeen },
    };
  });
}

// Sourced from server/campaignIntelligence.js -- one record per named
// campaign/operation, automatically extracted from news article text (no
// manually maintained list, see server/campaignExtraction.js), cross-
// referenced against the actor and malware entity stores for co-mentions.
function campaignIntelligenceChunks() {
  const entities = getCampaignEntities().slice(0, CAP.campaigns);
  return entities.map((c) => {
    const recentArticles = c.articles.slice(0, 5).map((a) => `"${a.title}" (${a.source}, ${a.publishedDate?.slice(0, 10)})`).join("; ");
    return {
      id: `campaign:${c.id}`,
      text:
        `Campaign/operation "${c.name}"${c.aliases.length ? ` (aliases: ${c.aliases.join(", ")})` : ""}` +
        `${c.verified ? " -- corroborated by multiple sources" : " -- reported by a single source so far, not yet corroborated"}. ` +
        `${c.description ? `${c.description} ` : ""}` +
        `${c.associatedActors.length ? `Associated actors: ${c.associatedActors.join(", ")}. ` : ""}` +
        `${c.associatedMalware.length ? `Associated malware/tools: ${c.associatedMalware.join(", ")}. ` : ""}` +
        `${c.targetedIndustries.length ? `Targets industries: ${c.targetedIndustries.join(", ")}. ` : ""}` +
        `${c.targetedCountries.length ? `Targets countries: ${c.targetedCountries.join(", ")}. ` : ""}` +
        `${c.cveExploited.length ? `Exploits: ${c.cveExploited.join(", ")}. ` : ""}` +
        `${recentArticles ? `Recent coverage: ${recentArticles}.` : ""}`,
      metadata: { type: "campaign", label: c.name, url: c.attackUrl, date: c.lastSeen },
    };
  });
}

function newsChunks() {
  const items = (cache.getEntry("news").data?.items ?? []).slice(0, CAP.news);
  return items.map((n) => ({
    id: `news:${n.link}`,
    text: `Security news (${n.source}, ${n.publishedDate?.slice(0, 10)}): "${n.title}"`,
    metadata: { type: "news", label: n.title, url: n.link, date: n.publishedDate },
  }));
}

/** Every chunk the RAG index is built from. See server/rag/indexer.js for how this is embedded and stored. */
export function buildChunks() {
  return [
    ...cveChunks(),
    ...kevChunks(),
    ...ransomwareChunks(),
    ...actorChunks(),
    ...techniqueChunks(),
    ...malwareChunks(),
    ...campaignIntelligenceChunks(),
    ...newsChunks(),
  ];
}
