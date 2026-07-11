// MISP Warning Lists (github.com/MISP/misp-warninglists) -- free, keyless,
// CC0 public-domain lists of known-benign infrastructure (CDNs, cloud
// provider IP ranges, top-N domain rankings, RFC1918 private ranges,
// dynamic-DNS domains, etc), community-maintained specifically to suppress
// false positives in threat-intel tooling. Confirmed live: 125 lists, ~118MB
// combined -- but that total is wildly skewed by 4 outlier files
// (windows-binary-hashes ~55MB, google-chrome-crux-1million ~25MB, tranco
// ~21MB, nioc-filehash ~10MB) that alone account for ~112MB of it. Excluding
// anything over MAX_LIST_BYTES drops the real in-memory footprint to ~6MB
// across the remaining ~121 lists -- deliberately conservative given this
// app already hit a real Render OOM crash once from an oversized in-memory
// dataset (see server/connectors/exploitdb.js's cveIndex and
// server/connectors/detectionRules.js's rule index for the same class of
// problem, caught the hard way).
//
// Reuses the existing GitHub client (server/githubIntel/githubClient.js) for
// exactly one tree listing (which also gives file sizes for the cap, no need
// to fetch content just to check) -- then downloads each qualifying list.json
// via raw.githubusercontent.com, which doesn't count against GitHub's API
// rate limit at all, same reasoning already documented in detectionRules.js.
//
// Deliberately does NOT wire this into the bulk Threat Feed table (checking
// all ~200 displayed IOCs against every list on every request) -- it's
// wired into IOC Search only, a single on-demand indicator per request,
// which keeps the cost bounded regardless of how large the warninglist
// index grows. Bulk suppression across the whole feed would be a real,
// separate feature with its own performance tradeoffs to design for, not a
// quick addition here.
import { getTree } from "../githubIntel/githubClient.js";
import { fetchText } from "../lib/http.js";

const OWNER = "MISP";
const REPO = "misp-warninglists";
const BRANCH = "main";
const MAX_LIST_BYTES = 2 * 1024 * 1024;

function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function parseCidr(entry) {
  if (entry.includes(":")) return null; // IPv6 not supported yet -- confirmed live all sampled cidr lists are IPv4
  const [ip, prefixStr] = entry.split("/");
  const ipInt = ipToInt(ip);
  const prefix = prefixStr !== undefined ? Number(prefixStr) : 32;
  if (ipInt === null || Number.isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: ipInt & mask, mask };
}

export default {
  id: "misp-warninglists",
  label: "MISP Warning Lists",
  intervalMs: 24 * 60 * 60 * 1000, // daily -- curated community lists, don't change intraday
  async fetch() {
    const tree = await getTree(OWNER, REPO, BRANCH);
    const allListFiles = tree.filter((t) => t.type === "blob" && t.path.startsWith("lists/") && t.path.endsWith("/list.json"));
    const listFiles = allListFiles.filter((f) => (f.size ?? 0) <= MAX_LIST_BYTES);
    const skippedLarge = allListFiles.length - listFiles.length;

    const exactMatches = new Map(); // normalized value -> Set<listName>
    const hostnameSuffixes = new Map(); // normalized suffix (no leading dot) -> Set<listName>
    const substringPatterns = []; // { pattern, listName }
    const cidrRanges = []; // { network, mask, listName }

    const results = await Promise.allSettled(
      listFiles.map(async (file) => {
        const url = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${BRANCH}/${file.path}`;
        const text = await fetchText(url, { source: "MISP Warning Lists", timeoutMs: 20_000 });
        return JSON.parse(text);
      }),
    );

    let loadedLists = 0;
    let totalEntries = 0;
    for (const result of results) {
      if (result.status !== "fulfilled") continue;
      const data = result.value;
      const listName = data.name ?? "Unknown list";
      loadedLists++;

      for (const raw of data.list ?? []) {
        const value = String(raw).trim();
        if (!value) continue;
        totalEntries++;

        if (data.type === "string") {
          const key = value.toLowerCase();
          const set = exactMatches.get(key) ?? new Set();
          set.add(listName);
          exactMatches.set(key, set);
        } else if (data.type === "hostname") {
          const key = value.replace(/^\./, "").toLowerCase();
          const set = hostnameSuffixes.get(key) ?? new Set();
          set.add(listName);
          hostnameSuffixes.set(key, set);
        } else if (data.type === "substring") {
          substringPatterns.push({ pattern: value.toLowerCase(), listName });
        } else if (data.type === "cidr") {
          const parsed = parseCidr(value);
          if (parsed) cidrRanges.push({ ...parsed, listName });
        }
        // "regex" type deliberately skipped -- not observed live in any
        // sampled list, and running arbitrary upstream regex patterns
        // against every IOC Search query is a needless ReDoS/perf risk for
        // a type that may not even be in active use.
      }
    }

    return { loadedLists, totalLists: allListFiles.length, skippedLarge, totalEntries, exactMatches, hostnameSuffixes, substringPatterns, cidrRanges };
  },
};

/**
 * Checks one IOC Search indicator against the synced warning-list index.
 * Returns the Set of list names it matched (empty if none) -- called live,
 * once per search, so this stays a cheap in-memory lookup, never a network
 * call. `data` is this connector's own cached `fetch()` result, passed in
 * by the caller (server/routes/dashboard.js already holds the cache
 * reference; this module doesn't import cache.js itself, same separation
 * every other connector keeps).
 */
export function matchWarninglists(type, value, data) {
  const matches = new Set();
  if (!data) return matches;
  const normalized = value.trim().toLowerCase();

  if (type === "ip") {
    const ipInt = ipToInt(normalized);
    if (ipInt !== null) {
      for (const range of data.cidrRanges) {
        if ((ipInt & range.mask) === range.network) matches.add(range.listName);
      }
    }
    for (const listName of data.exactMatches.get(normalized) ?? []) matches.add(listName);
    return matches;
  }

  if (type === "domain" || type === "url") {
    let hostname = normalized;
    if (type === "url") {
      try {
        hostname = new URL(normalized).hostname.toLowerCase();
      } catch {
        // not a parseable URL -- fall back to matching the raw value as-is
      }
    }

    for (const listName of data.exactMatches.get(hostname) ?? []) matches.add(listName);

    const labels = hostname.split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const suffix = labels.slice(i).join(".");
      for (const listName of data.hostnameSuffixes.get(suffix) ?? []) matches.add(listName);
    }

    for (const { pattern, listName } of data.substringPatterns) {
      if (hostname.includes(pattern)) matches.add(listName);
    }
    return matches;
  }

  // hash lookups: exact match only. Confirmed live the only free hash-shaped
  // warninglists (nioc-filehash) exceed the size cap and are excluded, so
  // this will almost always come back empty -- an honest "not on any small
  // known-benign hash list we track", not a broken feature.
  for (const listName of data.exactMatches.get(normalized) ?? []) matches.add(listName);
  return matches;
}
