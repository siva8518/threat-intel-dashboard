// CVE cross-reference correlation, used by the "click a CVE, see everything
// related" detail view. Built entirely from data this app already collects --
// no dedicated "CVE relationships" API exists for free:
//   - Related actors/campaigns/malware/techniques: reverse-lookup through the
//     ATT&CK graph's own CVE citations (group.cveIds / software.cveIds /
//     campaign.cveIds -- see server/connectors/attack.js), the same citation
//     data server/actorProfile.js already uses in the opposite direction.
//   - Related IOCs: threat-feed entries whose malwareFamily matches a malware
//     name pulled from the step above (IOCs aren't tagged with CVE IDs
//     directly, so this is one hop removed, not a direct match).
//   - GitHub PoCs: repos whose extracted CVE mentions (server/githubIntel/
//     extractor.js) include this CVE ID.
//   - News: keyword match against the CVE ID string, same pattern as
//     server/actorProfile.js's recentNews.
// Deliberately NOT included: GreyNoise activity. GreyNoise's free Community
// tier is an IP-reputation lookup keyed on an IP address -- there is no
// CVE-to-IP relationship in this app's data model (or in GreyNoise's own free
// API) to correlate against, so faking a "GreyNoise activity" section here
// would just be empty or fabricated. Documented in the frontend instead of
// silently omitted.
import { threatFeedIocs } from "./threatFeed.js";

function citesId(entity, cveId) {
  return (entity.cveIds ?? []).includes(cveId);
}

export function buildCveProfile(cveId, sources = {}) {
  const { attackData, newsItems, githubRepos } = sources;
  const groups = attackData?.groups ?? [];
  const software = attackData?.software ?? [];
  const campaigns = attackData?.campaigns ?? [];
  const techniques = attackData?.techniques ?? [];

  const citingGroups = groups.filter((g) => citesId(g, cveId));
  const citingCampaigns = campaigns.filter((c) => citesId(c, cveId));
  const citingSoftware = software.filter((s) => citesId(s, cveId));

  // A group is "related" if it directly cites the CVE, is attributed to a
  // campaign that cites it, or uses software that cites it -- these are the
  // same three attribution paths server/actorProfile.js's buildRelatedCves
  // draws citations from, just followed in reverse.
  const groupIds = new Set(citingGroups.map((g) => g.id));
  for (const c of citingCampaigns) if (c.groupId) groupIds.add(c.groupId);
  const citingSoftwareIds = new Set(citingSoftware.map((s) => s.id));
  for (const g of groups) if (g.softwareIds.some((id) => citingSoftwareIds.has(id))) groupIds.add(g.id);
  const relatedGroups = groups.filter((g) => groupIds.has(g.id));

  const softwareById = new Map(software.map((s) => [s.id, s]));
  const malwareNames = new Set(citingSoftware.map((s) => s.name));
  for (const g of relatedGroups) {
    for (const sid of g.softwareIds) {
      const s = softwareById.get(sid);
      if (s) malwareNames.add(s.name);
    }
  }

  const techniqueIds = new Set();
  for (const g of relatedGroups) for (const t of g.techniqueIds ?? []) techniqueIds.add(t);
  for (const s of citingSoftware) for (const t of s.techniqueIds ?? []) techniqueIds.add(t);
  const techniqueById = new Map(techniques.map((t) => [t.id, t]));
  const relatedTechniques = Array.from(techniqueIds)
    .map((id) => techniqueById.get(id))
    .filter(Boolean)
    .sort((a, b) => a.id.localeCompare(b.id));

  const lowerNames = Array.from(malwareNames).map((n) => n.toLowerCase());
  const relatedIocs = lowerNames.length
    ? threatFeedIocs()
        .filter((ioc) => lowerNames.includes((ioc.malwareFamily ?? "").toLowerCase()))
        .slice(0, 20)
    : [];

  const githubPocs = (githubRepos ?? [])
    .filter((r) => (r.extracted?.cveIds ?? []).includes(cveId))
    .slice(0, 10)
    .map((r) => ({ fullName: r.fullName, url: r.url, stars: r.stars, threatScore: r.threatScore?.score ?? r.threatScore ?? null }));

  const upperCveId = cveId.toUpperCase();
  const relatedNews = (newsItems ?? [])
    .filter((item) => item.title.toUpperCase().includes(upperCveId))
    .slice(0, 10)
    .map((item) => ({ id: item.link, title: item.title, link: item.link, source: item.source, publishedDate: item.publishedDate }));

  const relatedCampaigns = citingCampaigns.map((c) => ({ name: c.name, description: c.description, date: c.firstSeen, url: c.url }));

  return {
    cveId,
    relatedActors: relatedGroups.map((g) => ({ attackId: g.attackId, name: g.name, country: g.country, url: g.url })),
    relatedMalware: Array.from(malwareNames),
    relatedCampaigns,
    relatedTechniques,
    relatedIocs,
    githubPocs,
    relatedNews,
  };
}
