// CVE investigation module -- thin wrapper around the NVD/CIRCL lookup and
// server/cveProfile.js's already-built correlation engine (reverse-ATT&CK-
// citation walk for related actors/campaigns/malware/techniques, one-hop
// IOC match, GitHub PoC match, news keyword match). No new correlation
// logic needed here; this module just assembles the pieces the CVE route
// family already builds separately into one investigation result.
import { ApiError } from "../lib/http.js";
import * as cache from "../cache.js";
import { queryCves } from "../connectors/nvd.js";
import { correlateCves } from "../correlate.js";
import { lookupCve as lookupCveCircl } from "../lookups/circl.js";
import { buildCveProfile } from "../cveProfile.js";
import { getAllGithubRepos } from "../githubIntel/index.js";

export const type = "cve";

async function fetchCveRecord(cveId) {
  const result = await queryCves({ cveId, resultsPerPage: 1 });
  const record = result.records[0];
  if (record) {
    const kevEntries = cache.getEntry("cisa-kev").data?.entries ?? [];
    const epssScores = cache.getEntry("epss").data ?? {};
    const [enriched] = correlateCves([record], kevEntries, epssScores);
    return enriched;
  }
  try {
    return await lookupCveCircl(cveId);
  } catch (circlError) {
    if (circlError instanceof ApiError && circlError.status === 404) return null;
    throw circlError;
  }
}

export async function gather(value) {
  const cve = await fetchCveRecord(value);
  if (!cve) {
    return { found: false, cve: null, profile: null };
  }

  const profile = buildCveProfile(value, {
    attackData: cache.getEntry("attack").data,
    newsItems: cache.getEntry("news").data?.items ?? [],
    githubRepos: getAllGithubRepos(),
    exploitIndex: cache.getEntry("exploitdb").data?.cveIndex,
  });

  return { found: true, cve, profile };
}
