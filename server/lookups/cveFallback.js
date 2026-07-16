import { lookupCve } from "./circl.js";

// Fallback for the "Latest CVEs" default view when NVD's own cache is empty
// (a fresh server start during an NVD outage -- the more common "NVD is
// down mid-session" case already degrades gracefully by keeping the cache's
// last-known-good data, see server/cache.js). Deliberately reuses two
// connectors this app already has and trusts, rather than standing up a
// third, differently-shaped CVE data source:
//   1. server/connectors/cveProject.js -- the CVE Program's (cve.org) own
//      recently-reserved/updated CVE ID list, independent of NVD.
//   2. server/lookups/circl.js -- already this app's single-CVE fallback,
//      reused here per-ID to get description/vendor/severity.
// (CIRCL's own bulk `/api/last` endpoint was evaluated and rejected: live
// sample showed it's dominated by OSS-package advisories (PYSEC/GHSA) with
// only incidental CVE cross-references -- wrong shape and coverage for a
// general "latest CVEs across all vendors" list.)
const MAX_FALLBACK_LOOKUPS = 20; // CIRCL is free/keyless with no documented rate limit -- bounded the same conservative way as nvd.js's MAX_KEV_GAP_FILL_LOOKUPS
const CACHE_TTL_MS = 5 * 60 * 1000; // avoids re-hitting CIRCL with ~20 sequential lookups on every dashboard poll during an extended outage

let cached = null; // { fetchedAt, records }

export async function fetchFallbackCves(cveProjectData) {
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) return cached.records;

  const ids = [...(cveProjectData?.newCves ?? []), ...(cveProjectData?.updatedCves ?? [])]
    .map((e) => e.cveId)
    .filter((id, i, arr) => id && arr.indexOf(id) === i)
    .slice(0, MAX_FALLBACK_LOOKUPS);

  const records = [];
  for (const id of ids) {
    try {
      const record = await lookupCve(id);
      if (record) records.push(record);
    } catch {
      // best-effort -- CIRCL not having (or erroring on) one particular ID shouldn't abort the whole fallback
    }
  }

  cached = { fetchedAt: Date.now(), records };
  return records;
}
