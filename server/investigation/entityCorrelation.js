// Entity-Centric Correlation Engine -- builds "everything this platform
// knows about this entity" for a threat actor / malware family / ransomware
// group / campaign search, replacing the old "is this entity malicious?"
// bare-verdict behavior. See the approved plan at
// C:\Users\sivak\.claude\plans\moonlit-zooming-hopper.md for the full
// rationale. Every field below is assembled from stores/functions this
// platform already has -- no new ingestion, no new persisted store. The AI
// layer (shouldICare.js/correlationSummary.js) only narrates over this real
// data; it is never the source of truth for a relationship.
//
// Both entityModule.js (type="name") and ransomwareGroupModule.js
// (type="ransomwareGroup") call buildEntityDossier() so a search for "Clop"
// (a ransomware-tracker group name) gets the exact same correlation depth as
// a search for "LockBit" or "APT29" (a name-type search) -- previously these
// were two disjoint, differently-impoverished code paths.
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getDarkWebEntities } from "../darkWebIntelligence.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { getAllGithubRepos } from "../githubIntel/index.js";
import { searchEntitiesByName, findAiReportsByEntityName } from "./crossReference.js";
import { resolveCanonicalAlias, KNOWN_ALIAS_GROUPS } from "./knownAliasGroups.js";
import { mergeThreatActors, detectionRulesFor, techniqueIdsForFamily } from "../correlate.js";
import { buildEntityHuntingQueries } from "../huntingLibrary.js";
import { buildCveProfile } from "../cveProfile.js";
import { norm } from "./entityLookup.js";
import * as cache from "../cache.js";

// A campaign/entity is "current" if last observed within this window --
// documented, deterministic, never a guess. Entities with no lastSeen at all
// go to a third "undated" bucket rather than being silently defaulted into
// either current or historical.
const CURRENT_WINDOW_DAYS = 365;
const CAP_MATCHED_ENTITIES = 5;
const IOC_BUCKET_TYPES = ["ip", "domain", "url", "hash", "email"];

function bucketForCampaign(entity) {
  if (!entity.lastSeen) return "undated";
  const days = (Date.now() - new Date(entity.lastSeen).getTime()) / 86_400_000;
  return days <= CURRENT_WINDOW_DAYS ? "current" : "historical";
}

/** Flattens iocs+articleIocs across every matched malware entity into a per-type inventory with real counts -- the source data already exists on MalwareIntelligenceEntity, this is pure aggregation, no new ingestion. */
function aggregateIocInventory(malwareEntities) {
  const buckets = new Map(IOC_BUCKET_TYPES.map((t) => [t, new Map()]));
  for (const entity of malwareEntities) {
    for (const ioc of [...(entity.iocs ?? []), ...(entity.articleIocs ?? [])]) {
      const map = buckets.get(ioc.indicatorType);
      if (!map) continue; // an indicatorType outside the 5 tracked bucket types (e.g. registryKey) -- not part of this inventory
      const key = norm(ioc.indicator);
      if (map.has(key)) continue; // first-seen family wins; dedupes across entities and across iocs/articleIocs
      map.set(key, { indicator: ioc.indicator, firstSeen: ioc.firstSeen ?? null, lastSeen: ioc.firstSeen ?? null, source: entity.name });
    }
  }
  return IOC_BUCKET_TYPES.map((type) => {
    const items = Array.from(buckets.get(type).values());
    return { indicatorType: type, count: items.length, items: items.slice(0, 50) };
  }).filter((b) => b.count > 0);
}

function iocCountForMalwareNames(names, malwareEntities) {
  const wanted = new Set((names ?? []).map(norm));
  let count = 0;
  for (const m of malwareEntities) {
    if (wanted.has(norm(m.name))) count += (m.iocs?.length ?? 0) + (m.articleIocs?.length ?? 0);
  }
  return count;
}

function initialAccessTechniquesFor(malwareNames, attackIndex, softwareIndex) {
  const ids = new Set();
  for (const name of malwareNames ?? []) for (const id of techniqueIdsForFamily(name, softwareIndex)) ids.add(id);
  return Array.from(ids)
    .map((id) => attackIndex.find((t) => t.id === id))
    .filter((t) => t && /initial access/i.test(t.tactic ?? ""))
    .map((t) => ({ id: t.id, name: t.name }));
}

/**
 * CVE mini-profiles -- actor/campaign entities carry a real `cveExploited[]`
 * field (ATT&CK cveIds + news-text match), reused directly as DIRECT
 * relationships. Malware entities carry NO CVE field at all (confirmed gap,
 * documented in investigationGraph.js#gatherMalware's own
 * unavailableRelationships) -- a malware family's CVEs are derived only
 * TRANSITIVELY, via actors known to use that family, and always labeled
 * INFERRED. Never fabricates a direct malware<->CVE citation.
 */
function buildAssociatedCves(actors, campaigns, malwareEntities) {
  const direct = new Map();
  for (const actor of actors) {
    for (const id of actor.cveExploited ?? []) {
      if (!direct.has(id)) direct.set(id, { cveId: id, relationship: "direct", source: `Direct: threat actor "${actor.name}"'s own tracked CVE exploitation record (ATT&CK + news text match)`, campaignRelationship: [] });
    }
  }
  for (const campaign of campaigns) {
    for (const id of campaign.cveExploited ?? []) {
      const entry = direct.get(id) ?? { cveId: id, relationship: "direct", source: `Direct: campaign "${campaign.name}"'s own tracked CVE exploitation record (ATT&CK + news text match)`, campaignRelationship: [] };
      entry.campaignRelationship.push(campaign.name);
      direct.set(id, entry);
    }
  }

  const inferred = new Map();
  for (const malware of malwareEntities) {
    const usingActors = actors.filter((a) => (a.malwareUsed ?? []).some((m) => norm(m) === norm(malware.name)));
    for (const actor of usingActors) {
      for (const id of actor.cveExploited ?? []) {
        if (direct.has(id) || inferred.has(id)) continue;
        inferred.set(id, { cveId: id, relationship: "inferred", source: `INFERRED -- via threat actor "${actor.name}"'s own CVE record, not a first-party malware↔CVE citation`, campaignRelationship: [] });
      }
    }
  }

  const attackData = cache.getEntry("attack").data;
  const newsItems = cache.getEntry("news").data?.items ?? [];
  const githubRepos = getAllGithubRepos();
  const exploitIndex = cache.getEntry("exploitdb").data?.cveIndex;

  return [...direct.values(), ...inferred.values()].slice(0, 30).map((entry) => {
    const profile = buildCveProfile(entry.cveId, { attackData, newsItems, githubRepos, exploitIndex });
    const exploitationContext = profile.exploits?.length
      ? `${profile.exploits.length} known exploit(s) tracked on Exploit-DB${profile.githubPocs?.length ? " / GitHub PoCs" : ""}.`
      : profile.githubPocs?.length
        ? `${profile.githubPocs.length} GitHub proof-of-concept repositor${profile.githubPocs.length === 1 ? "y" : "ies"} found.`
        : profile.relatedNews?.length
          ? `${profile.relatedNews.length} news article(s) reference this CVE.`
          : null;
    return {
      cveId: entry.cveId,
      relationship: entry.relationship,
      source: entry.source,
      exploitationContext,
      // Vendor/product lookup intentionally not fetched per-CVE here -- would
      // require N live/cached NVD/CIRCL lookups for a single name search
      // that may match many CVEs; the analyst can pivot to the CVE itself
      // (see the CVE Investigation Workspace) for that detail.
      affectedTech: null,
      campaignRelationship: entry.campaignRelationship,
      confidenceLabel: entry.relationship === "direct" ? "DIRECT" : "MODERATE",
    };
  });
}

function buildAttackTechniques(actors, malwareEntities) {
  const attackData = cache.getEntry("attack").data;
  const attackIndex = attackData?.techniques ?? [];
  const softwareIndex = attackData?.software ?? [];
  const byId = new Map();
  for (const actor of actors) {
    for (const id of actor.techniqueIds ?? []) {
      if (byId.has(id)) continue;
      const t = attackIndex.find((x) => x.id === id);
      byId.set(id, { id, name: t?.name ?? id, tactic: t?.tactic ?? null, observedVia: `Threat actor "${actor.name}"`, source: "Direct: actor.techniqueIds (ATT&CK)" });
    }
  }
  for (const malware of malwareEntities) {
    for (const id of techniqueIdsForFamily(malware.name, softwareIndex)) {
      if (byId.has(id)) continue;
      const t = attackIndex.find((x) => x.id === id);
      byId.set(id, { id, name: t?.name ?? id, tactic: t?.tactic ?? null, observedVia: `Malware family "${malware.name}"`, source: "Reverse: ATT&CK software techniqueIds / curated map" });
    }
  }
  return Array.from(byId.values());
}

/**
 * Victim/targeting aggregation -- `matchNames` is the union of every name
 * this entity could plausibly be recorded under (the search value itself,
 * every matched actor's own name/aliases, every known-alias-group member),
 * so a bare ransomware-tracker group with NO ThreatActorIntelligence entity
 * (e.g. "Clop" if it has no news-derived actor record) still resolves real
 * victim data instead of coming back empty just because no actor entity
 * existed to drive the match.
 */
function buildVictimsTargeting(matchNames, malwareEntities) {
  const malwareNames = new Set(malwareEntities.map((m) => norm(m.name)));
  const ransomwareVictims = getRansomwareCampaigns().filter((r) => matchNames.has(norm(r.group)));
  const darkWebVictims = getDarkWebEntities().filter(
    (d) => (d.associatedActors ?? []).some((a) => matchNames.has(norm(a))) || (d.associatedMalware ?? []).some((m) => malwareNames.has(norm(m))),
  );

  const byIndustry = new Map();
  const byCountry = new Map();
  const sample = [];
  for (const r of ransomwareVictims) {
    if (r.sector && r.sector !== "Unknown") byIndustry.set(r.sector, (byIndustry.get(r.sector) ?? 0) + 1);
    if (r.country && r.country !== "Unknown") byCountry.set(r.country, (byCountry.get(r.country) ?? 0) + 1);
    if (sample.length < 20) sample.push({ victim: r.victim, sector: r.sector && r.sector !== "Unknown" ? r.sector : null, country: r.country && r.country !== "Unknown" ? r.country : null, discoveredDate: r.discoveredDate, source: "Ransomware Victim Tracking (ransomware.live / RansomWatch / RansomLook)" });
  }
  for (const d of darkWebVictims) {
    for (const c of d.targetedCountries ?? []) byCountry.set(c, (byCountry.get(c) ?? 0) + 1);
    if (sample.length < 20) sample.push({ victim: d.victimOrg ?? d.name, sector: null, country: d.targetedCountries?.[0] ?? null, discoveredDate: d.firstSeen ?? null, source: "Dark Web Intelligence" });
  }

  return {
    totalVictims: ransomwareVictims.length + darkWebVictims.length,
    byIndustry: Array.from(byIndustry.entries()).map(([industry, count]) => ({ industry, count })).sort((a, b) => b.count - a.count),
    byCountry: Array.from(byCountry.entries()).map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count),
    sample,
  };
}

function buildDetectionAndHunting(malwareEntities, actors) {
  const ruleIndex = cache.getEntry("detection-rules").data?.index ?? [];
  const seenRules = new Set();
  const detectionRules = [];
  for (const entity of [...malwareEntities, ...actors]) {
    for (const rule of detectionRulesFor(entity.name, ruleIndex)) {
      const k = `${rule.label}:${rule.path}`;
      if (seenRules.has(k)) continue;
      seenRules.add(k);
      detectionRules.push(rule);
    }
  }
  const seenHunts = new Set();
  const huntingQueries = [];
  for (const item of buildEntityHuntingQueries(malwareEntities, actors, ruleIndex)) {
    const k = `${item.platform}:${item.query}`;
    if (seenHunts.has(k)) continue;
    seenHunts.add(k);
    huntingQueries.push({ platform: item.platformLabel, query: item.query, description: item.articleTitle });
  }
  return { detectionRules, huntingQueries };
}

// Preferred primary-entity precedence: malware first (most often what an
// analyst pivots from an IOC to check), then a Ransomware/APT actor, then
// any actor, then a campaign -- same order entityModule.js/verdictEngine.js
// already agreed on, kept here as the one shared implementation.
function pickPrimaryEntity(malware, actors, campaigns) {
  if (malware.length > 0) return { type: "malware", name: malware[0].name };
  const primaryActor = actors.find((a) => a.type === "Ransomware" || a.type === "APT") ?? actors[0];
  if (primaryActor) return { type: "actor", name: primaryActor.name };
  if (campaigns.length > 0) return { type: "campaign", name: campaigns[0].name };
  return null;
}

/**
 * @param {string} searchValue
 * @param {{ seedType: "name" | "ransomwareGroup" }} opts
 * @returns {Promise<import("../../src/types/threat-intel.js").EntityDossier & { _matchedMalware: unknown[], _matchedActors: unknown[], _matchedCampaigns: unknown[], _ransomwareOnly: unknown[] }>}
 */
export async function buildEntityDossier(searchValue, { seedType }) {
  const canonical = resolveCanonicalAlias(searchValue);
  const searchTarget = canonical ?? searchValue;

  const { malware, actors, campaigns } = searchEntitiesByName(searchTarget);

  const otxSignals = cache.getEntry("otx").data?.actorSignals ?? [];
  const merged = mergeThreatActors(getRansomwareCampaigns(), otxSignals, actors);
  const alreadyCovered = new Set(actors.map((a) => norm(a.name)));
  const q = norm(searchTarget);
  const ransomwareOnly = merged.filter((a) => norm(a.name).includes(q) && !alreadyCovered.has(norm(a.name))).slice(0, 10);

  const trackerVictims = getRansomwareCampaigns().filter((r) => norm(r.group) === norm(searchTarget));
  const hasVerifiedProfile = malware.length > 0 || actors.length > 0 || campaigns.length > 0;
  const sourceType = hasVerifiedProfile ? "verified-profile" : trackerVictims.length > 0 ? "ransomware-tracker-only" : "unverified-mention";

  const cappedMalware = malware.slice(0, CAP_MATCHED_ENTITIES);
  const cappedActors = actors.slice(0, CAP_MATCHED_ENTITIES);
  const cappedCampaigns = campaigns.slice(0, CAP_MATCHED_ENTITIES);

  const aliasSet = new Set();
  for (const e of [...malware, ...actors, ...campaigns]) for (const a of e.aliases ?? []) aliasSet.add(a);
  const allMatchedNames = new Set([norm(searchTarget), ...[...malware, ...actors, ...campaigns].map((e) => norm(e.name))]);
  for (const group of KNOWN_ALIAS_GROUPS) {
    const groupNames = [group.canonical, ...group.aliases].map(norm);
    if (!groupNames.some((n) => allMatchedNames.has(n))) continue;
    if (norm(group.canonical) !== norm(searchTarget)) aliasSet.add(group.canonical);
    for (const a of group.aliases) if (norm(a) !== norm(searchTarget)) aliasSet.add(a);
  }
  const aliases = Array.from(aliasSet);

  const iocInventory = aggregateIocInventory(cappedMalware);
  const iocCount = iocInventory.reduce((sum, b) => sum + b.count, 0);

  const associatedCves = buildAssociatedCves(cappedActors, cappedCampaigns, cappedMalware);

  const attackData = cache.getEntry("attack").data;
  const attackIndex = attackData?.techniques ?? [];
  const softwareIndex = attackData?.software ?? [];

  const campaignHistory = cappedCampaigns.map((c) => {
    const actorNamesForCampaign = new Set((c.associatedActors ?? []).map(norm));
    const victims = getRansomwareCampaigns().filter((r) => actorNamesForCampaign.has(norm(r.group)));
    return {
      name: c.name,
      bucket: bucketForCampaign(c),
      firstSeen: c.firstSeen ?? null,
      lastSeen: c.lastSeen ?? null,
      targetedIndustries: c.targetedIndustries ?? [],
      targetedCountries: c.targetedCountries ?? [],
      associatedMalware: c.associatedMalware ?? [],
      cveIds: c.cveExploited ?? [],
      initialAccessTechniques: initialAccessTechniquesFor(c.associatedMalware, attackIndex, softwareIndex),
      victimCount: victims.length,
      iocCount: iocCountForMalwareNames(c.associatedMalware, cappedMalware),
      sources: (c.articles ?? []).slice(0, 3).map((a) => a.source),
    };
  });

  const attackTechniques = buildAttackTechniques(cappedActors, cappedMalware);

  const actorMatchNames = new Set([norm(searchTarget), ...cappedActors.flatMap((a) => [norm(a.name), ...(a.aliases ?? []).map(norm)]), ...aliases.map(norm)]);
  const victimsTargeting = buildVictimsTargeting(actorMatchNames, cappedMalware);

  const reportNames = [searchTarget, ...aliases, ...cappedMalware.map((m) => m.name), ...cappedActors.map((a) => a.name), ...cappedCampaigns.map((c) => c.name)];
  const threatReports = findAiReportsByEntityName(reportNames);

  const { detectionRules, huntingQueries } = buildDetectionAndHunting(cappedMalware, cappedActors);

  return {
    sourceType,
    primaryEntity: pickPrimaryEntity(malware, actors, campaigns),
    aliases,
    malwareFamilyCount: malware.length,
    campaignCount: campaignHistory.length,
    cveCount: associatedCves.length,
    iocCount,
    victimCount: victimsTargeting.totalVictims,
    threatReportCount: threatReports.length,
    campaigns: campaignHistory,
    associatedCves,
    iocInventory,
    attackTechniques,
    victimsTargeting,
    threatReports,
    detectionRules,
    huntingQueries,
    // Internal-only (not part of the public EntityDossier type) -- lets
    // entityModule.js/ransomwareGroupModule.js's thin wrappers (Phase 1)
    // build their own existing return shapes without re-searching.
    _matchedMalware: malware,
    _matchedActors: actors,
    _matchedCampaigns: campaigns,
    _ransomwareOnly: ransomwareOnly,
    _searchTarget: searchTarget,
  };
}
