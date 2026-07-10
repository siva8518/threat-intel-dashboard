import { fetchJson } from "../lib/http.js";

const RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/recentvictims";

/**
 * ransomware.live: free, keyless feed of ransomware-group leak-site posts
 * (group name, victim, sector, date). This is the only source in this
 * project's list that tracks ransomware campaigns / group activity in bulk
 * -- it's what powers both "Active ransomware campaigns" and the
 * ransomware-group half of "Threat actor activity". It does NOT cover
 * APT/nation-state actors; there's no free bulk-attribution feed for that.
 */
export default {
  id: "ransomware-live",
  label: "ransomware.live",
  intervalMs: 30 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(RANSOMWARE_LIVE_URL, { source: "ransomware.live" });

    // Confirmed live against api.ransomware.live: fields are `group`, `victim`,
    // `activity` (sector), `discovered`, and `url` (public ransomware.live page --
    // NOT `claim_url`, which is the dark-web .onion leak-site link).
    return (Array.isArray(data) ? data : []).map((entry) => ({
      id: `${entry.group}-${entry.victim}-${entry.discovered}`,
      group: entry.group ?? "Unknown",
      victim: entry.victim ?? "Unknown",
      sector: entry.activity ?? "Unknown",
      country: entry.country ?? "Unknown",
      discoveredDate: entry.discovered ? new Date(entry.discovered).toISOString() : new Date().toISOString(),
      sourceUrl: entry.url ?? null,
    }));
  },
};
