// Shared deduped-threat-feed builder. Factored out of routes/dashboard.js so
// both the dashboard routes and the GitHub intel enrichment connector
// (server/githubIntel/) can correlate against the exact same IOC set without
// duplicating the source list -- keeping THREAT_FEED_IDS in one place means
// adding a new source only needs one edit, not two that can drift apart.
import * as cache from "./cache.js";
import { dedupeIocs } from "./correlate.js";

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

export function threatFeedIocs() {
  const lists = THREAT_FEED_IDS.map((id) => capRecent(cache.getEntry(id).data ?? []));
  const otxData = cache.getEntry("otx").data;
  if (otxData?.iocs) lists.push(capRecent(otxData.iocs));
  return dedupeIocs(lists);
}
