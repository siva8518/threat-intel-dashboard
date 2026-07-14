// Tags each security-news headline with the entities it mentions (CVE,
// threat actor, malware family, industry, country) plus a derived severity
// and a "breaking" flag, so the frontend can group/filter/highlight without
// re-deriving any of this itself. Reuses the exact same substring-matching
// approach already established elsewhere in this app (server/actorProfile.js's
// `mentionsActor`, server/cveProfile.js's CVE-ID matching, server/correlate.js's
// sector->industry bucket map) -- headline text is noisy, so this is a
// documented best-effort heuristic, not NLP/NER. Known false-positive risk,
// same as elsewhere in this app: a handful of actor/country names are also
// common English words or given names (e.g. the "Play" ransomware group,
// "Jordan" the country) and can over-match; accepted here for the same
// reason it was accepted for actor matching -- there's no free NLP entity
// extractor to do better, and an occasional false tag is far less harmful
// than silently tagging nothing.
import countryNames from "./data/country-names.json" with { type: "json" };
import industryMap from "./data/industry-map.json" with { type: "json" };
import { splitFamilies, getCommonAttackToolNames } from "./correlationEngine.js";

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;
const BREAKING_WINDOW_MS = 6 * 60 * 60 * 1000; // 6 hours -- most security blogs post a few times/day, so this is "still hot"
const MIN_NAME_LENGTH = 4; // skip matching names shorter than this -- too likely to false-positive as a normal word/substring

// Headline urgency language -- confirmed by scanning real headlines from this
// app's own news feeds for how outlets actually phrase high-severity stories.
// Widened after a live audit found real severe stories (a 73k-device
// credential exposure, two "Critical Vulnerabilities"/"Critical ... Flaw"
// SAP headlines, a CISA KEV-catalog addition, a pre-auth RCE, a perfect-10
// CVSS Joomla bug, a GitHub Actions supply-chain compromise) all landing as
// "low" purely because the original list only matched a handful of exact
// singular phrasings -- see CRITICAL_VULN_PATTERN below for the plural/
// word-order cases a flat list can't cover.
const URGENT_KEYWORDS = [
  "zero-day",
  "zero day",
  "0-day",
  "actively exploited",
  "actively exploiting",
  "actively hacking",
  "mass exploitation",
  "emergency patch",
  "critical vulnerability",
  "critical vulnerabilities",
  "critical flaw",
  "critical flaws",
  "critical bug",
  "critical bugs",
  "nation-state",
  "state-sponsored",
  "ransomware attack",
  "data breach",
  "data exposed",
  "credentials exposed",
  "breach exposes",
  "under attack",
  "widespread attacks",
  "in the wild",
  "major security event",
  "remote code execution",
  "arbitrary code execution",
  "arbitrary command execution",
  "authentication bypass",
  "pre-authentication",
  "pre-auth",
  "unauthenticated remote",
  "supply chain compromise",
  "supply chain attack",
  "kev catalog",
  "known exploited vulnerabilities catalog",
  "perfect 10",
  "cvss 10",
  "cvss score of 10",
  "backdoor",
];

// Catches "Critical Vulnerabilities in X" / "Critical ... Flaw" phrasing the
// flat keyword list above misses purely from plural/word-order variation --
// "critical" followed within a short span by a vulnerability-ish root.
const CRITICAL_VULN_PATTERN = /critical\b[^.]{0,25}\b(vulnerabilit\w*|flaw\w*|bug\w*|exploit\w*)/i;

// Standalone "RCE" acronym, word-boundary so it doesn't match inside
// unrelated words that happen to contain the letters ("Commerce", "source").
const RCE_ACRONYM_PATTERN = /\brce\b/i;

function norm(s) {
  return (s ?? "").trim().toLowerCase();
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Word-boundary matching, not plain substring -- confirmed live that plain
 * `.includes()` matched the ATT&CK software "Ping" inside "Wiping"/"Mapping"
 * and "Disco" inside "discovered", tagging headlines with tools they never
 * mentioned. `\b` isn't quite right for multi-word names with punctuation,
 * so this also accepts a non-alphanumeric boundary on each side.
 */
function matchNames(title, names) {
  const hits = new Set();
  for (const name of names) {
    if (!name || name.length < MIN_NAME_LENGTH) continue;
    const re = new RegExp(`(?:^|[^a-z0-9])${escapeRegExp(name.toLowerCase())}(?:[^a-z0-9]|$)`, "i");
    if (re.test(title)) hits.add(name);
  }
  return Array.from(hits);
}

export function matchCveIds(title) {
  return Array.from(new Set((title.match(CVE_PATTERN) ?? []).map((id) => id.toUpperCase())));
}

/**
 * Map<cveId, count> of how many news headlines (across every configured
 * source, including any just-added RSS feed -- this is a live regex scan of
 * whatever's currently cached, not a separately-maintained list) name each
 * CVE. Merged into server/githubIntel/index.js#computeTopCves the same way
 * server/attackTechniqueIntelligence.js#getNewsTechniqueCounts is merged into
 * computeAttackTechniquesObserved, so "Top CVEs" reflects news attention too,
 * not just GitHub PoC/repo activity.
 */
export function getNewsCveCounts(newsItems) {
  const counts = new Map();
  for (const item of newsItems ?? []) {
    for (const cveId of matchCveIds(item.title)) counts.set(cveId, (counts.get(cveId) ?? 0) + 1);
  }
  return counts;
}

export function matchIndustries(title) {
  const lowerTitle = norm(title);
  const hits = [];
  for (const [bucket, keywords] of Object.entries(industryMap)) {
    if (bucket.startsWith("_")) continue;
    if (keywords.some((k) => lowerTitle.includes(k))) hits.push(bucket);
  }
  return hits;
}

export function matchCountries(title) {
  const hits = [];
  for (const name of Object.values(countryNames)) {
    if (typeof name !== "string") continue;
    const re = new RegExp(`(?:^|[^a-z0-9])${escapeRegExp(name.toLowerCase())}(?:[^a-z0-9]|$)`, "i");
    if (re.test(title)) hits.push(name);
  }
  return hits;
}

function computeSeverity({ cveIds, hasUrgentKeyword, kevIds, epssScores, actors, malware }) {
  const anyKev = cveIds.some((id) => kevIds.has(id));
  const anyHighEpss = cveIds.some((id) => (epssScores[id]?.score ?? 0) >= 0.5);
  if (anyKev || anyHighEpss) return "critical";
  if (hasUrgentKeyword) return "high";
  if (cveIds.length > 0 || actors.length > 0 || malware.length > 0) return "medium";
  return "low";
}

/**
 * @param {Array} newsItems - {id, title, link, source, publishedDate}
 * @param {object} sources
 * @param {string[]} sources.actorNames - ATT&CK group names/aliases + ransomware group names, deduped
 * @param {string[]} sources.malwareNames - ATT&CK software names/aliases + curated malware-family names, deduped
 * @param {Set<string>} sources.kevIds
 * @param {object} sources.epssScores - cveId -> { score, percentile }
 */
export function tagNewsItems(newsItems, sources) {
  const { actorNames, malwareNames, kevIds, epssScores } = sources;
  const now = Date.now();

  return newsItems.map((item) => {
    const cveIds = matchCveIds(item.title);
    const actors = matchNames(item.title, actorNames);
    const malware = matchNames(item.title, malwareNames);
    const industries = matchIndustries(item.title);
    const countries = matchCountries(item.title);
    const hasUrgentKeyword =
      URGENT_KEYWORDS.some((k) => item.title.toLowerCase().includes(k)) ||
      CRITICAL_VULN_PATTERN.test(item.title) ||
      RCE_ACRONYM_PATTERN.test(item.title);

    return {
      ...item,
      tags: { cveIds, actors, malware, industries, countries },
      severity: computeSeverity({ cveIds, hasUrgentKeyword, kevIds, epssScores, actors, malware }),
      isBreaking: now - new Date(item.publishedDate).getTime() <= BREAKING_WINDOW_MS,
    };
  });
}

/**
 * Builds the actor/malware name lists from already-cached data and tags
 * `newsItems` in one call -- used by /dashboard/news.
 */
export function getTaggedNewsItems({ newsItems, attackData, ransomwareCampaigns, threatFeedIocs, kevEntries, epssScores }) {
  const actorNames = new Set();
  for (const g of attackData?.groups ?? []) for (const n of [g.name, ...(g.aliases ?? [])]) actorNames.add(n);
  for (const c of ransomwareCampaigns ?? []) actorNames.add(c.group);

  const commonTools = getCommonAttackToolNames(attackData);
  const malwareNames = new Set();
  for (const s of attackData?.software ?? []) {
    if (commonTools.has(s.name.toLowerCase())) continue;
    for (const n of [s.name, ...(s.aliases ?? [])]) malwareNames.add(n);
  }
  for (const ioc of threatFeedIocs ?? []) for (const fam of splitFamilies(ioc.malwareFamily)) malwareNames.add(fam);

  return tagNewsItems(newsItems ?? [], {
    actorNames: Array.from(actorNames),
    malwareNames: Array.from(malwareNames),
    kevIds: new Set((kevEntries ?? []).map((e) => e.cveId)),
    epssScores: epssScores ?? {},
  });
}
