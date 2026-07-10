import { fetchJson } from "../lib/http.js";

const DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json";

/**
 * The official CVE Program's (cve.org / CVEProject) own recently-changed
 * list -- distinct from NVD, which enriches published CVEs with CVSS/CPE
 * data, often days after they're reserved. This is the raw record feed
 * itself: which CVE IDs were newly added or updated in the last sync cycle,
 * straight from the CVE Program's own cvelistV5 repository. Confirmed live
 * shape: `{ fetchTime, numberOfChanges, new: [...], updated: [...] }`, each
 * entry `{ cveId, cveOrgLink, githubLink, dateUpdated }`.
 */
export default {
  id: "cve-project",
  label: "CVE Program (cve.org)",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(DELTA_URL, { source: "CVE Program" });
    const toEntry = (e) => ({ cveId: e.cveId, dateUpdated: e.dateUpdated, url: e.cveOrgLink });

    return {
      fetchedAt: data.fetchTime ?? new Date().toISOString(),
      newCves: (data.new ?? []).map(toEntry),
      updatedCves: (data.updated ?? []).map(toEntry),
    };
  },
};
