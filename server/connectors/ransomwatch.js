import { fetchJson } from "../lib/http.js";

const RANSOMWATCH_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json";
const RECENT_LIMIT = 150;

function toIso(discovered) {
  const iso = new Date(discovered.replace(" ", "T") + "Z");
  return Number.isNaN(iso.getTime()) ? new Date().toISOString() : iso.toISOString();
}

/**
 * RansomWatch: free, keyless JSON snapshot of ransomware leak-site posts
 * scraped from Tor hidden services (github.com/joshhighet/ransomwatch).
 * `posts.json` is the ENTIRE historical archive (16,000+ entries back to
 * 2020), so only the most recent RECENT_LIMIT are kept. Fields: only
 * `post_title`/`group_name`/`discovered`, no sector/country breakdown
 * (unlike ransomware.live) -- merged with ransomware.live and RansomLook in
 * server/ransomwareCampaigns.js.
 *
 * CONFIRMED LIVE: this project's automated scraper appears to have stopped
 * -- `posts.json`'s own commit history shows its last real update was
 * 2025-06-16 (over a year stale at the time of writing), despite the repo
 * itself still receiving unrelated commits since. Kept in this app anyway
 * since it's free and still technically serves valid (if stale) historical
 * data that corroborates against the two actively-updating trackers, but
 * synced daily rather than every 30 min -- no point polling faster than a
 * feed that hasn't changed in over a year.
 */
export default {
  id: "ransomwatch",
  label: "RansomWatch (confirmed stale since 2025-06-16)",
  intervalMs: 24 * 60 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(RANSOMWATCH_URL, { source: "RansomWatch" });
    const posts = Array.isArray(data) ? data : [];

    return posts
      .sort((a, b) => new Date(b.discovered).getTime() - new Date(a.discovered).getTime())
      .slice(0, RECENT_LIMIT)
      .map((entry) => ({
        id: `ransomwatch-${entry.group_name}-${entry.post_title}-${entry.discovered}`,
        group: entry.group_name ?? "Unknown",
        victim: entry.post_title ?? "Unknown",
        sector: "Unknown",
        country: "Unknown",
        discoveredDate: entry.discovered ? toIso(entry.discovered) : new Date().toISOString(),
        sourceUrl: null,
      }));
  },
};
