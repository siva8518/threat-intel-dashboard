import { fetchJson } from "../lib/http.js";

const RANSOMLOOK_URL = "https://www.ransomlook.io/api/recent";

function toIso(discovered) {
  const iso = new Date(discovered.replace(" ", "T") + "Z");
  return Number.isNaN(iso.getTime()) ? new Date().toISOString() : iso.toISOString();
}

/**
 * RansomLook: free, keyless API of ransomware leak-site posts
 * (ransomlook.io). Confirmed live: `/api/recent` is already capped to the
 * most recent 100 posts server-side (unlike RansomWatch's full-archive
 * dump), with the same thin shape -- no sector/country breakdown -- merged
 * with ransomware.live and RansomWatch in server/ransomwareCampaigns.js.
 */
export default {
  id: "ransomlook",
  label: "RansomLook",
  intervalMs: 30 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(RANSOMLOOK_URL, { source: "RansomLook" });
    const posts = Array.isArray(data) ? data : [];

    return posts.map((entry) => ({
      id: `ransomlook-${entry.group_name}-${entry.post_title}-${entry.discovered}`,
      group: entry.group_name ?? "Unknown",
      victim: entry.post_title ?? "Unknown",
      sector: "Unknown",
      country: "Unknown",
      discoveredDate: entry.discovered ? toIso(entry.discovered) : new Date().toISOString(),
      // Confirmed live: `link` is relative to the leak site's own (often
      // .onion) domain, e.g. "/news.php?id=1" -- RansomLook's API never
      // exposes that base domain, so a relative value here isn't a usable
      // standalone URL. Only keep it when it's already absolute.
      sourceUrl: /^https?:\/\//.test(entry.link ?? "") ? entry.link : null,
    }));
  },
};
