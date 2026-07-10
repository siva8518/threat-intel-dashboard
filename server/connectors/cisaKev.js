import { fetchJson } from "../lib/http.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/** CISA Known Exploited Vulnerabilities catalog. Free, no auth. */
export default {
  id: "cisa-kev",
  label: "CISA KEV",
  intervalMs: 30 * 60 * 1000, // 30 min -- catalog only updates a few times/week
  async fetch() {
    const data = await fetchJson(KEV_URL, { source: "CISA KEV" });
    return {
      count: data.count,
      dateReleased: data.dateReleased,
      entries: data.vulnerabilities.map((v) => ({
        cveId: v.cveID,
        vendorProject: v.vendorProject,
        product: v.product,
        vulnerabilityName: v.vulnerabilityName,
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        requiredAction: v.requiredAction,
        ransomwareUse: v.knownRansomwareCampaignUse === "Known",
      })),
    };
  },
};
