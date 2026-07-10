// Threat Actor Profile assembly. Primary source is MITRE ATT&CK (Groups,
// Software, Campaigns, and the relationships between them -- see
// server/connectors/attack.js). Everything else here is enrichment: cross-
// referencing the actor's name/aliases against data this app already
// collects from other sources (OTX, the deduped threat feed, ransomware.live,
// security news, NVD), rather than a dedicated "threat actor" API, because no
// free source maps CVEs/news/IOCs to specific named actors directly.
import { queryCves } from "./connectors/nvd.js";
import { searchPulses } from "./connectors/otx.js";
import { getActorDetail } from "./connectors/malpedia.js";

const RELATED_CVE_LIMIT = 8;
const NVD_ENRICH_LIMIT = 6; // cap live per-CVE NVD lookups per profile view
const OTX_CAMPAIGN_LIMIT = 8;

function normalize(text) {
  return (text ?? "").toLowerCase();
}

/** True if `text` mentions the actor's name or any of its aliases (simple substring match, not NLP). */
function mentionsActor(text, group) {
  const lower = normalize(text);
  if (!lower) return false;
  if (lower.includes(group.name.toLowerCase())) return true;
  return group.aliases.some((alias) => lower.includes(alias.toLowerCase()));
}

/** True if `text` case-insensitively mentions any of `candidates` (non-empty strings only). */
function mentionsAny(text, candidates) {
  const lower = normalize(text);
  if (!lower) return false;
  return candidates.some((c) => c && lower.includes(c.toLowerCase()));
}

/** Lightweight list for the search/picker UI. */
export function listThreatActors(attackData) {
  return (attackData?.groups ?? [])
    .map((g) => ({ attackId: g.attackId, name: g.name, aliases: g.aliases, country: g.country }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Case-insensitive search by name or alias substring. */
export function searchThreatActors(attackData, query) {
  const q = normalize(query);
  if (!q) return listThreatActors(attackData);
  return listThreatActors(attackData).filter(
    (a) => a.name.toLowerCase().includes(q) || a.aliases.some((alias) => alias.toLowerCase().includes(q)),
  );
}

/**
 * Assembles the full profile for one actor. `sources` bundles the other
 * cached data this correlates against -- all optional/best-effort, a missing
 * source just means that section of the profile comes back empty rather than
 * failing the whole profile.
 */
export async function buildThreatActorProfile(attackId, attackData, sources = {}) {
  const group = (attackData?.groups ?? []).find((g) => g.attackId === attackId);
  if (!group) return null;

  const softwareById = new Map((attackData.software ?? []).map((s) => [s.id, s]));
  const techniqueById = new Map((attackData.techniques ?? []).map((t) => [t.id, t]));
  const campaignById = new Map((attackData.campaigns ?? []).map((c) => [c.id, c]));

  const software = group.softwareIds.map((id) => softwareById.get(id)).filter(Boolean);
  const malwareUsed = software.filter((s) => s.type === "malware").map((s) => ({ name: s.name, aliases: s.aliases, url: s.url }));
  const toolsUsed = software.filter((s) => s.type === "tool").map((s) => ({ name: s.name, aliases: s.aliases, url: s.url }));
  const techniques = group.techniqueIds.map((id) => techniqueById.get(id)).filter(Boolean).sort((a, b) => a.id.localeCompare(b.id));

  const rawCampaigns = group.campaignIds.map((id) => campaignById.get(id)).filter(Boolean);
  const attackCampaigns = rawCampaigns.map((c) => ({ source: "MITRE ATT&CK", name: c.name, description: c.description, date: c.firstSeen, url: c.url }));

  const ransomwareCampaigns = (sources.ransomwareCampaigns ?? [])
    .filter((c) => mentionsActor(c.group, group))
    .map((c) => ({ source: "ransomware.live", name: `${c.group} vs. ${c.victim}`, description: `${c.sector}, ${c.country}`, date: c.discoveredDate, url: c.sourceUrl }));

  // Threat feed IOCs report the malware family actually used (e.g. "X-Agent",
  // "Zebrocy"), not the actor's own codename -- matching against this
  // group's own software names/aliases (in addition to the actor's own
  // name/aliases) catches real hits that name-only matching would miss.
  const softwareNames = software.flatMap((s) => [s.name, ...s.aliases]);
  const relatedMalware = (sources.threatFeedIocs ?? [])
    .filter((ioc) => mentionsActor(ioc.malwareFamily, group) || mentionsAny(ioc.malwareFamily, softwareNames))
    .slice(0, 20)
    .map((ioc) => ({ indicator: ioc.indicator, indicatorType: ioc.indicatorType, malwareFamily: ioc.malwareFamily, firstSeen: ioc.firstSeen, sources: ioc.sources }));

  const recentNews = (sources.newsItems ?? [])
    .filter((item) => mentionsActor(item.title, group))
    .slice(0, 10)
    .map((item) => ({ id: item.link, title: item.title, link: item.link, source: item.source, publishedDate: item.publishedDate }));

  const [relatedCves, otxCampaigns, malpediaMalware] = await Promise.all([
    buildRelatedCves(group, rawCampaigns, software),
    buildOtxCampaigns(group),
    buildMalpediaMalware(group, sources.malpediaActors),
  ]);

  const relatedCampaigns = [...attackCampaigns, ...ransomwareCampaigns, ...otxCampaigns].sort((a, b) => new Date(b.date ?? 0) - new Date(a.date ?? 0));

  const timeline = [
    ...attackCampaigns.map((c) => ({ date: c.date, label: `ATT&CK campaign ${c.name}`, url: c.url })),
    ...ransomwareCampaigns.map((c) => ({ date: c.date, label: c.name, url: c.url })),
    ...otxCampaigns.map((c) => ({ date: c.date, label: `OTX: ${c.name}`, url: c.url })),
    ...recentNews.map((n) => ({ date: n.publishedDate, label: n.title, url: n.link })),
    ...relatedCves.filter((c) => c.publishedDate).map((c) => ({ date: c.publishedDate, label: `${c.id} published`, url: c.sourceUrl })),
  ]
    .filter((e) => e.date)
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  return {
    attackId: group.attackId,
    name: group.name,
    aliases: group.aliases,
    description: group.description,
    url: group.url,
    country: group.country,
    motivations: group.motivations,
    activeSince: group.activeSince,
    targetIndustries: group.targetIndustries,
    malwareUsed,
    toolsUsed,
    malpediaMalware,
    techniques,
    relatedCampaigns,
    relatedCves,
    relatedMalware,
    recentNews,
    timeline,
  };
}

/**
 * Related CVEs: primarily the CVE IDs MITRE ATT&CK itself cites in this
 * group's/its campaigns'/its software's own citation text -- confirmed live
 * these are genuinely actor-specific (e.g. Velvet Ant's own citation reads
 * "... Exploits Cisco Zero-Day (CVE-2024-20399)"), a much stronger signal
 * than generic NVD keyword search on the actor's name, which almost never
 * matches (CVE descriptions describe the vulnerability, not who exploited
 * it -- confirmed live against several well-known group names/aliases).
 * Each cited ID is enriched with real severity/description via a live
 * single-CVE NVD lookup where possible, falling back to a bare ID+link if
 * NVD is unreachable/rate-limited for that ID. NVD keyword search on the
 * actor's name is kept as a last-resort topper-upper since it's free and
 * occasionally does surface something.
 */
async function buildRelatedCves(group, rawCampaigns, software) {
  const citedIds = new Set(group.cveIds ?? []);
  for (const c of rawCampaigns) for (const id of c.cveIds ?? []) citedIds.add(id);
  for (const s of software) for (const id of s.cveIds ?? []) citedIds.add(id);

  const idsToEnrich = Array.from(citedIds).slice(0, NVD_ENRICH_LIMIT);
  const enriched = await Promise.allSettled(idsToEnrich.map((id) => queryCves({ cveId: id, resultsPerPage: 1 })));

  const cves = idsToEnrich.map((id, i) => {
    const outcome = enriched[i];
    const record = outcome.status === "fulfilled" ? outcome.value.records[0] : null;
    if (record) {
      return { id: record.id, description: record.description, severity: record.severity, publishedDate: record.publishedDate, sourceUrl: record.sourceUrl };
    }
    return {
      id,
      description: "Cited by MITRE ATT&CK as associated with this actor's activity (live NVD lookup unavailable right now).",
      severity: "UNKNOWN",
      publishedDate: "",
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${id}`,
    };
  });

  if (cves.length < RELATED_CVE_LIMIT) {
    try {
      const result = await queryCves({ keywordSearch: group.name, resultsPerPage: RELATED_CVE_LIMIT - cves.length });
      for (const cve of result.records) {
        if (citedIds.has(cve.id)) continue;
        cves.push({ id: cve.id, description: cve.description, severity: cve.severity, publishedDate: cve.publishedDate, sourceUrl: cve.sourceUrl });
      }
    } catch {
      // best-effort topper-upper; a failure here shouldn't fail the whole profile
    }
  }

  return cves.slice(0, RELATED_CVE_LIMIT);
}

/**
 * Related Campaigns (OTX): a live full-text pulse search for this actor's
 * name, not the bulk-synced "recent activity" window (`server/connectors/
 * otx.js`'s scheduled `fetch()`), which only covers ~100 of OTX's 44,000+
 * pulses at any moment and rarely happens to include a given actor. Every
 * raw search hit is re-verified with `mentionsActor` against its own name +
 * description before being kept, since OTX's search is a loose/fuzzy match,
 * not an exact phrase search -- confirmed live that querying "Velvet Ant"
 * returns zero pulses that actually mention it, while "APT28"/"Lazarus
 * Group" return pages of genuinely relevant ones.
 */
async function buildOtxCampaigns(group) {
  try {
    const results = await searchPulses(group.name);
    return results
      .filter((p) => mentionsActor(`${p.name} ${p.description ?? ""}`, group))
      .map((p) => ({
        source: "OTX",
        name: p.name,
        description: (p.description ?? "").replace(/\s+/g, " ").trim().slice(0, 300),
        date: p.created,
        url: `https://otx.alienvault.com/pulse/${p.id}`,
      }))
      .sort((a, b) => new Date(b.date) - new Date(a.date))
      .slice(0, OTX_CAMPAIGN_LIMIT);
  } catch {
    return []; // OTX search is enrichment; not configured or a transient failure shouldn't fail the whole profile
  }
}

function slugify(name) {
  return name.toLowerCase().trim().replace(/\s+/g, "_").replace(/[^a-z0-9_]/g, "");
}

/**
 * Malpedia (Fraunhofer FKIE) actor-to-malware-family attribution -- a
 * second, independently-curated source alongside MITRE ATT&CK's own Software
 * list, occasionally covering families ATT&CK doesn't. `malpediaActors` is
 * this app's own cached list of every Malpedia actor slug (confirmed live:
 * lowercase, spaces replaced with underscores, e.g. "lazarus_group",
 * "apt28") -- tried against the actor's name and each alias so we don't miss
 * a match just because ATT&CK and Malpedia use different capitalization/
 * spacing for the same actor.
 */
async function buildMalpediaMalware(group, malpediaActors) {
  if (!malpediaActors?.length) return [];

  const actorSlugs = new Set(malpediaActors);
  const candidateSlugs = [group.name, ...group.aliases].map(slugify);
  const slug = candidateSlugs.find((c) => actorSlugs.has(c));
  if (!slug) return [];

  try {
    const detail = await getActorDetail(slug);
    return Object.entries(detail.families ?? {}).map(([familySlug, info]) => ({
      name: info.common_name || familySlug,
      aliases: info.alt_names ?? [],
      url: `https://malpedia.caad.fkie.fraunhofer.de/details/${familySlug}`,
    }));
  } catch {
    return []; // Malpedia enrichment is best-effort; a failed lookup shouldn't fail the whole profile
  }
}
