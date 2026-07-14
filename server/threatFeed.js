// Shared deduped-threat-feed builder. Factored out of routes/dashboard.js so
// both the dashboard routes and the GitHub intel enrichment connector
// (server/githubIntel/) can correlate against the exact same IOC set without
// duplicating the source list -- keeping THREAT_FEED_IDS in one place means
// adding a new source only needs one edit, not two that can drift apart.
import * as cache from "./cache.js";
import { dedupeIocs } from "./correlate.js";
import { getAllGithubRepos } from "./githubIntel/index.js";

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

export function threatFeedIocs() {
  const lists = THREAT_FEED_IDS.map((id) => capRecent(cache.getEntry(id).data ?? []));
  const otxData = cache.getEntry("otx").data;
  if (otxData?.iocs) lists.push(capRecent(otxData.iocs));
  lists.push(capRecent(githubRepoIocs()));
  return dedupeIocs(lists);
}
