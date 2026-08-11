// Shared deduped-threat-feed builder. Factored out of routes/dashboard.js so
// both the dashboard routes and the GitHub intel enrichment connector
// (server/githubIntel/) can correlate against the exact same IOC set without
// duplicating the source list -- keeping THREAT_FEED_IDS in one place means
// adding a new source only needs one edit, not two that can drift apart.
import * as cache from "./cache.js";
import { dedupeIocs } from "./correlate.js";
import { getAllGithubRepos } from "./githubIntel/index.js";
import { getAllEntities as getIocIntelligenceEntities } from "./iocIntelligence.js";

const THREAT_FEED_IDS = [
  "urlhaus",
  "threatfox",
  "malwarebazaar",
  "feodotracker",
  "openphish",
  "abuseipdb",
  "pulsedive",
  "phishtank",
  "emerging-threats",
  "spamhaus",
];
const PER_SOURCE_CAP = 40;

/**
 * Take each source's own most-recent N entries before merging. Without this,
 * a source with no real per-item timestamp (OpenPhish stamps everything with
 * "now" at sync time) sorts to the very top of a pure recency merge and can
 * crowd out every other source entirely -- confirmed live: adding OTX's
 * 1500+ real IOCs still produced a 100%-OpenPhish top-150 until this cap was
 * added, since OpenPhish's ~100 "now"-stamped entries all outranked OTX's
 * genuinely-timestamped (but slightly older) ones.
 */
function capRecent(list) {
  return [...list].sort((a, b) => new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime()).slice(0, PER_SOURCE_CAP);
}

/**
 * Indicators (hashes/IPs/domains) GitHub Intel's own extractor (server/
 * githubIntel/extractor.js) already pulled out of a repo's README/content --
 * previously only used to check whether they matched an *existing* feed
 * entry (server/githubIntel/enrich.js#correlateIndicators), never surfaced
 * as feed entries in their own right, so a repo-only indicator (never seen
 * by URLHaus/ThreatFox/etc.) was invisible everywhere outside that one
 * repo's own detail page. Only surfaced when the same repo's text also
 * named a known malware family -- otherwise there's no meaningful family to
 * attach the indicator to, and an un-attributed hash/IP isn't worth adding
 * noise for.
 */
function githubRepoIocs() {
  const iocs = [];
  for (const repo of getAllGithubRepos()) {
    const extracted = repo.extracted;
    const malwareFamily = extracted?.malwareFamilies?.[0];
    if (!malwareFamily) continue;
    const firstSeen = repo.lastEnrichedAt ?? repo.discoveredAt;

    const push = (indicator, indicatorType) =>
      iocs.push({
        id: `github-${repo.fullName}-${indicatorType}-${indicator}`,
        indicator,
        indicatorType,
        malwareFamily,
        threatType: "GitHub-Referenced",
        firstSeen,
        source: "GitHub Intel",
      });

    for (const h of [...(extracted.sha256 ?? []), ...(extracted.sha1 ?? []), ...(extracted.md5 ?? [])]) push(h, "hash");
    for (const ip of [...(extracted.ipv4 ?? []), ...(extracted.ipv6 ?? [])]) push(ip, "ip");
    for (const d of extracted.domains ?? []) push(d, "domain");
  }
  return iocs;
}

const CANONICAL_TYPE_TO_IOC_TYPE = { ipv4: "ip", ipv6: "ip", domain: "domain", url: "url", sha256: "hash", sha1: "hash", md5: "hash" };

/**
 * Canonical, source-agnostic IOC store (server/iocIntelligence.js) -- unlike
 * every list above, these records persist their real `firstSeen` across
 * cache cycles instead of being replaced wholesale on every sync (see
 * server/cache.js#setSuccess), so this is the only source in this feed that
 * can actually be filtered to a date earlier than the current sync cycle.
 * Confirmed live: every other list here is either a genuinely recent-only
 * upstream API (ThreatFox's own query is `days: 3`) or gets re-capped to its
 * newest 40 entries every cycle (capRecent above), so a date-range filter
 * further back than a day or two always returned nothing before this was
 * added -- not a UI bug, the data simply never existed anywhere else.
 * Deliberately NOT run through capRecent -- capping here would silently
 * reintroduce the exact "recent-only" gap this exists to fix. Only
 * malicious_observed records are surfaced (infrastructure_context/
 * benign_reference/unknown are real extractions but not threat indicators in
 * their own right -- see server/iocClassification.js) and only the 4 bucket
 * types this feed's UI understands (ip/domain/url/hash).
 */
function canonicalIocFeedEntries() {
  const entries = [];
  for (const record of getIocIntelligenceEntities()) {
    if (record.classification !== "malicious_observed") continue;
    const indicatorType = CANONICAL_TYPE_TO_IOC_TYPE[record.type];
    if (!indicatorType) continue;
    entries.push({
      id: `ioc-intel-${record.id}`,
      indicator: record.value,
      indicatorType,
      malwareFamily: record.aggregatedAssociations?.malwareFamilies?.[0] || "Unknown",
      threatType: "Extracted Indicator",
      firstSeen: record.firstSeen,
      source: "IOC Extraction Pipeline",
    });
  }
  return entries;
}

export function threatFeedIocs() {
  const lists = THREAT_FEED_IDS.map((id) => capRecent(cache.getEntry(id).data ?? []));
  const otxData = cache.getEntry("otx").data;
  if (otxData?.iocs) lists.push(capRecent(otxData.iocs));
  lists.push(capRecent(githubRepoIocs()));
  lists.push(canonicalIocFeedEntries());
  return dedupeIocs(lists);
}
