import malwareAttackMap from "./data/malware-attack-map.json" with { type: "json" };
import industryMap from "./data/industry-map.json" with { type: "json" };
import countryCodes from "./data/country-codes.json" with { type: "json" };

const TRENDING_MALWARE_LIMIT = 15;
const ATTACK_TECHNIQUES_LIMIT = 15;
const HEATMAP_INDUSTRIES = ["LSHC", "TMT", "FSI", "Consumer"];
const HEATMAP_TOP_ACTORS = 10;
const GEO_TOP_ACTORS_PER_COUNTRY = 3;

/** Attaches KEV cross-reference + EPSS score/percentile onto each CVE record. */
export function correlateCves(cveRecords, kevEntries, epssScores) {
  const kevIds = new Set((kevEntries ?? []).map((e) => e.cveId));
  const epss = epssScores ?? {};

  return cveRecords.map((record) => ({
    ...record,
    knownExploited: kevIds.has(record.id),
    epssScore: epss[record.id]?.score ?? null,
    epssPercentile: epss[record.id]?.percentile ?? null,
  }));
}

function iocKey(ioc) {
  return `${ioc.indicatorType}:${ioc.indicator.trim().toLowerCase()}`;
}

/**
 * Merges IOC lists from multiple sources into one deduped list -- the same
 * indicator often shows up in more than one feed (e.g. a URLHaus URL that's
 * also in OpenPhish). Keeps every contributing source instead of silently
 * dropping the duplicate, and keeps the earliest first-seen timestamp.
 */
export function dedupeIocs(iocLists) {
  const byKey = new Map();

  for (const ioc of iocLists.flat()) {
    const key = iocKey(ioc);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...ioc, sources: [ioc.source] });
      continue;
    }

    existing.sources = Array.from(new Set([...existing.sources, ioc.source]));
    if (new Date(ioc.firstSeen) < new Date(existing.firstSeen)) existing.firstSeen = ioc.firstSeen;
    if (existing.malwareFamily === "Unknown" && ioc.malwareFamily !== "Unknown") {
      existing.malwareFamily = ioc.malwareFamily;
    }
  }

  return Array.from(byKey.values()).sort((a, b) => new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime());
}

/** Case-insensitive substring match against the curated malware->ATT&CK seed map. */
function techniqueIdsForFamily(malwareFamily) {
  if (!malwareFamily || malwareFamily === "Unknown" || malwareFamily === "N/A") return [];
  const lower = malwareFamily.toLowerCase();
  const ids = new Set();
  for (const [family, techniqueIds] of Object.entries(malwareAttackMap)) {
    if (family.startsWith("_")) continue;
    if (lower.includes(family)) techniqueIds.forEach((id) => ids.add(id));
  }
  return Array.from(ids);
}

function resolveTechnique(id, attackIndex) {
  const found = attackIndex.find((t) => t.id === id);
  return found ?? { id, name: id, tactic: "unknown", url: `https://attack.mitre.org/techniques/${id}` };
}

/**
 * Cross-references a name (malware family or threat actor) against the
 * YARA-Rules/SigmaHQ filename-word index (server/connectors/detectionRules.js)
 * via case-insensitive substring match -- same matching philosophy as
 * techniqueIdsForFamily above. Filenames in both repos are consistently
 * organized by what they detect, so this is a reasonable "does a public
 * detection rule likely exist for this?" signal, not a guarantee.
 */
// Below this length, a substring match is too likely to be a coincidence
// (e.g. the generic rule-filename word "fake" matching inside the malware
// family name "ClearFake") -- only exact-length-or-longer words are trusted
// for substring matching; shorter ones must match exactly.
const MIN_FUZZY_WORD_LENGTH = 6;

export function detectionRulesFor(name, ruleIndex) {
  if (!name || !ruleIndex?.length) return [];
  const lower = name.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (lower.length < 3) return [];

  const seen = new Set();
  const matches = [];
  for (const row of ruleIndex) {
    const isMatch = row.word === lower || (row.word.length >= MIN_FUZZY_WORD_LENGTH && (lower.includes(row.word) || row.word.includes(lower)));
    if (!isMatch) continue;
    const key = `${row.label}:${row.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    matches.push({ label: row.label, path: row.path, url: row.url });
    if (matches.length >= 5) break;
  }
  return matches;
}

/**
 * Aggregates IOC malware-family frequency into a "trending malware" list.
 * Each entry gets whatever ATT&CK techniques the curated map associates with
 * it, so this doubles as the raw material for computeAttackTechniques below.
 */
export function computeTrendingMalware(iocs, attackIndex, ruleIndex = []) {
  const counts = new Map();
  for (const ioc of iocs) {
    if (!ioc.malwareFamily || ioc.malwareFamily === "Unknown" || ioc.malwareFamily === "N/A") continue;
    // Split combined values like "exe, AgentTesla" (URLHaus tags) into individual families.
    for (const family of ioc.malwareFamily.split(",").map((f) => f.trim()).filter(Boolean)) {
      const entry = counts.get(family) ?? { family, count: 0, sources: new Set() };
      entry.count += 1;
      entry.sources.add(ioc.source);
      counts.set(family, entry);
    }
  }

  return Array.from(counts.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, TRENDING_MALWARE_LIMIT)
    .map((entry) => ({
      family: entry.family,
      count: entry.count,
      sources: Array.from(entry.sources),
      techniques: techniqueIdsForFamily(entry.family).map((id) => resolveTechnique(id, attackIndex)),
      detectionRules: detectionRulesFor(entry.family, ruleIndex),
    }));
}

/** Aggregates ATT&CK technique frequency across all IOCs, via the same curated map. */
export function computeAttackTechniquesObserved(iocs, attackIndex) {
  const counts = new Map();
  for (const ioc of iocs) {
    for (const id of techniqueIdsForFamily(ioc.malwareFamily)) {
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }

  return Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, ATTACK_TECHNIQUES_LIMIT)
    .map(([id, count]) => ({ ...resolveTechnique(id, attackIndex), observedCount: count }));
}

// The current MITRE ATT&CK Enterprise tactics, in kill-chain order -- spelled
// exactly as `attack.js`'s connector produces them (STIX kill_chain_phases[0]
// .phase_name with hyphens replaced by spaces). Confirmed live against the
// real bundle rather than assumed: the classic 14-tactic list (with a single
// "Defense Evasion" tactic) is stale -- the live Enterprise matrix has split
// that into two separate tactics, "Defense Impairment" and "Stealth" (e.g.
// T1055 Process Injection and T1027 Obfuscated Files or Information both
// carry "stealth", not "defense-evasion", as of this bundle), making this a
// 15-tactic list now.
const ATTACK_TACTICS_ORDER = [
  "reconnaissance", "resource development", "initial access", "execution", "persistence",
  "privilege escalation", "defense impairment", "stealth", "credential access", "discovery",
  "lateral movement", "collection", "command and control", "exfiltration", "impact",
];
const TOP_TECHNIQUES_PER_TACTIC = 5;

/**
 * ATT&CK Tactic Heat Map: same underlying technique-frequency data as
 * computeAttackTechniquesObserved above, but grouped and summed by tactic
 * (kill-chain stage) instead of truncated to the top 15 individual
 * techniques -- a proper heat map needs every tactic represented, including
 * the "cold" ones with zero hits, not just whichever techniques happen to
 * rank highest overall.
 */
export function computeAttackTacticHeatmap(iocs, attackIndex) {
  const techniqueCounts = new Map(); // techniqueId -> count
  for (const ioc of iocs) {
    for (const id of techniqueIdsForFamily(ioc.malwareFamily)) {
      techniqueCounts.set(id, (techniqueCounts.get(id) ?? 0) + 1);
    }
  }

  const byTactic = new Map(); // tactic -> [{id, name, url, count}]
  for (const [id, count] of techniqueCounts) {
    const technique = resolveTechnique(id, attackIndex);
    const list = byTactic.get(technique.tactic) ?? [];
    list.push({ id: technique.id, name: technique.name, url: technique.url, count });
    byTactic.set(technique.tactic, list);
  }

  const tactics = ATTACK_TACTICS_ORDER.map((tactic) => {
    const techniques = (byTactic.get(tactic) ?? []).sort((a, b) => b.count - a.count);
    const total = techniques.reduce((sum, t) => sum + t.count, 0);
    return { tactic, total, techniques: techniques.slice(0, TOP_TECHNIQUES_PER_TACTIC) };
  });

  const maxTotal = Math.max(1, ...tactics.map((t) => t.total));
  return tactics.map((t) => ({ ...t, intensity: t.total / maxTotal }));
}

/**
 * Combines ransomware.live campaign data (primary, bulk, keyless) with OTX
 * pulse "adversary" tags (secondary, community-sourced) into one threat-actor
 * list. Ransomware groups are the only reliably-attributed actors here --
 * OTX adversary names are informational, not verified.
 */
export function mergeThreatActors(ransomwareCampaigns, otxActorSignals) {
  const byGroup = new Map();

  for (const campaign of ransomwareCampaigns ?? []) {
    const entry = byGroup.get(campaign.group) ?? { name: campaign.group, type: "ransomware", campaignCount: 0, lastActivity: campaign.discoveredDate };
    entry.campaignCount += 1;
    if (new Date(campaign.discoveredDate) > new Date(entry.lastActivity)) entry.lastActivity = campaign.discoveredDate;
    byGroup.set(campaign.group, entry);
  }

  for (const signal of otxActorSignals ?? []) {
    const entry = byGroup.get(signal.name) ?? { name: signal.name, type: "otx-tagged", campaignCount: 0, lastActivity: signal.date };
    entry.campaignCount += 1;
    if (new Date(signal.date) > new Date(entry.lastActivity)) entry.lastActivity = signal.date;
    byGroup.set(signal.name, entry);
  }

  return Array.from(byGroup.values()).sort((a, b) => new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime());
}

/**
 * Case-insensitive substring match against the curated sector->industry-bucket
 * seed map. Exported so routes/dashboard.js can tag each ransomware campaign
 * with its bucket for client-side industry filtering (see the Executive
 * Threat Summary's "Industries Targeted" click-through).
 */
export function industryForSector(sector) {
  if (!sector) return "Other";
  const lower = sector.toLowerCase();
  for (const bucket of HEATMAP_INDUSTRIES) {
    if ((industryMap[bucket] ?? []).some((keyword) => lower.includes(keyword))) return bucket;
  }
  return "Other";
}

/**
 * Homepage heat map: which ransomware groups have recently hit which
 * industries, filtered to one region (US by default). Built entirely from
 * ransomware.live's own `activity` (sector) and `country` fields -- no
 * separate industry-classification source exists for free, so this reuses
 * the same campaign data already powering the Ransomware Campaigns section.
 */
export function computeActorIndustryHeatmap(campaigns, { country = "US" } = {}) {
  // `country: null` means "every country" -- used by the Executive Threat
  // Summary's global industries-targeted rollup, as opposed to the homepage
  // heat map widget's single-region view.
  const regional = country ? (campaigns ?? []).filter((c) => c.country === country) : (campaigns ?? []);

  const cellCounts = new Map(); // `${actor}|${industry}` -> count
  const actorTotals = new Map();
  const industryTotals = new Map();

  for (const campaign of regional) {
    const industry = industryForSector(campaign.sector);
    industryTotals.set(industry, (industryTotals.get(industry) ?? 0) + 1);

    if (!HEATMAP_INDUSTRIES.includes(industry)) continue; // "Other" only counted in industryTotals, not the actor grid
    const key = `${campaign.group}|${industry}`;
    cellCounts.set(key, (cellCounts.get(key) ?? 0) + 1);
    actorTotals.set(campaign.group, (actorTotals.get(campaign.group) ?? 0) + 1);
  }

  const topActors = Array.from(actorTotals.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, HEATMAP_TOP_ACTORS)
    .map(([name]) => name);

  const cells = [];
  for (const actor of topActors) {
    for (const industry of HEATMAP_INDUSTRIES) {
      cells.push({ actor, industry, count: cellCounts.get(`${actor}|${industry}`) ?? 0 });
    }
  }

  return {
    region: country,
    industries: HEATMAP_INDUSTRIES,
    actors: topActors,
    cells,
    industryTotals: [...HEATMAP_INDUSTRIES, "Other"].map((industry) => ({
      industry,
      count: industryTotals.get(industry) ?? 0,
    })),
    sampleSize: regional.length,
  };
}

/**
 * Global geo-targeting: which countries recent ransomware campaigns hit, and
 * which actors were behind them, for the homepage map. Same underlying
 * ransomware.live campaign data as the industry heat map, aggregated by
 * country instead of industry -- no separate geo-IP source needed since
 * ransomware.live already reports victim country per post.
 */
export function computeGeoTargeting(campaigns) {
  const byCountry = new Map(); // alpha2 -> { count, actorCounts: Map<actor, count> }

  for (const campaign of campaigns ?? []) {
    const alpha2 = campaign.country;
    if (!alpha2 || alpha2 === "Unknown" || !countryCodes[alpha2]) continue;

    const entry = byCountry.get(alpha2) ?? { count: 0, actorCounts: new Map() };
    entry.count += 1;
    entry.actorCounts.set(campaign.group, (entry.actorCounts.get(campaign.group) ?? 0) + 1);
    byCountry.set(alpha2, entry);
  }

  const countries = Array.from(byCountry.entries())
    .map(([alpha2, entry]) => ({
      countryCode: alpha2,
      numericId: countryCodes[alpha2],
      count: entry.count,
      topActors: Array.from(entry.actorCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, GEO_TOP_ACTORS_PER_COUNTRY)
        .map(([name, count]) => ({ name, count })),
    }))
    .sort((a, b) => b.count - a.count);

  return { countries, sampleSize: (campaigns ?? []).length };
}
