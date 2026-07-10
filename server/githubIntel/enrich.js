import { queryCves } from "../connectors/nvd.js";

// Persists for the process lifetime (not per-enrichment-cycle): CVE
// name/severity/description rarely change, and the same well-known CVEs
// (e.g. Log4Shell, PrintNightmare) tend to show up across many repos --
// caching avoids a redundant live NVD call for every repeat mention.
const cveDetailCache = new Map();

/**
 * Cross-references extracted indicators (domains/urls/IPs/hashes) against
 * the same deduped threat feed already powering the rest of this dashboard
 * (server/routes/dashboard.js#threatFeedIocs). A GitHub PoC repo mentioning a
 * domain that's already in URLHaus is a much stronger signal than the domain
 * appearing in isolation.
 */
export function correlateIndicators(extracted, threatFeedIocs) {
  const byIndicator = new Map(threatFeedIocs.map((ioc) => [ioc.indicator.toLowerCase(), ioc]));

  const candidates = [
    ...extracted.domains,
    ...extracted.urls,
    ...extracted.ipv4,
    ...extracted.ipv6,
    ...extracted.sha256,
    ...extracted.sha1,
    ...extracted.md5,
  ];

  const matches = [];
  const matchedSources = new Set();
  for (const indicator of candidates) {
    const found = byIndicator.get(indicator.toLowerCase());
    if (!found) continue;
    matches.push({ indicator, indicatorType: found.indicatorType, malwareFamily: found.malwareFamily, sources: found.sources });
    found.sources.forEach((s) => matchedSources.add(s));
  }

  const allSources = new Set(threatFeedIocs.flatMap((ioc) => ioc.sources));

  return { matches, matchedFeeds: matchedSources.size, feedsChecked: allSources.size };
}

/**
 * Enriches one CVE ID with CVSS/severity/description (live NVD lookup, cached
 * process-wide) plus KEV/EPSS (already-cached data this app collects on its
 * own schedule -- no extra network call needed for those two).
 */
export async function enrichCve(cveId, { kevEntries = [], epssScores = {} } = {}) {
  const knownExploited = kevEntries.some((e) => e.cveId === cveId);
  const epss = epssScores[cveId] ?? null;
  const epssFields = { epssScore: epss?.score ?? null, epssPercentile: epss?.percentile ?? null };

  if (!cveDetailCache.has(cveId)) {
    let record = null;
    try {
      const result = await queryCves({ cveId, resultsPerPage: 1 });
      const cve = result.records[0];
      if (cve) {
        record = {
          id: cve.id,
          description: cve.description,
          severity: cve.severity,
          cvssScore: cve.cvssScore,
          publishedDate: cve.publishedDate,
          sourceUrl: cve.sourceUrl,
        };
      }
    } catch {
      record = null; // best-effort enrichment; a failed lookup for one CVE shouldn't fail the whole repo
    }
    cveDetailCache.set(cveId, record);
  }

  const cached = cveDetailCache.get(cveId);
  if (cached) return { ...cached, knownExploited, ...epssFields };

  return {
    id: cveId,
    description: null,
    severity: "UNKNOWN",
    cvssScore: null,
    publishedDate: null,
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${cveId}`,
    knownExploited,
    ...epssFields,
  };
}

export async function enrichCves(cveIds, sources) {
  return Promise.all(cveIds.map((id) => enrichCve(id, sources)));
}

/** How many other repos in the store reference at least one of the same CVE IDs -- corroboration signal for threatScoring.js. */
export function countCorroboratingRepos(cveIds, allRepos, currentRepoFullName) {
  if (cveIds.length === 0) return 0;
  const cveSet = new Set(cveIds);
  return allRepos.filter(
    (r) => r.fullName !== currentRepoFullName && (r.extracted?.cveIds ?? []).some((id) => cveSet.has(id)),
  ).length;
}
