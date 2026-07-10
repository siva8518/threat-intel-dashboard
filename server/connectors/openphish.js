import { fetchText } from "../lib/http.js";

const OPENPHISH_URL = "https://openphish.com/feed.txt";

/**
 * OpenPhish community feed. Plain text, one URL per line, no metadata -- so
 * first-seen is "now" (sync time) and malware family is N/A. Server-side,
 * CORS is irrelevant (that only applies to browser fetches); Node's fetch
 * just follows openphish.com's redirect to its GitHub raw-content mirror
 * automatically.
 */
export default {
  id: "openphish",
  label: "OpenPhish",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const text = await fetchText(OPENPHISH_URL, { source: "OpenPhish" });
    const fetchedAt = new Date().toISOString();

    return text
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((url, index) => {
        let host = url;
        try {
          host = new URL(url).host;
        } catch {
          // leave host as the raw string if it isn't a valid URL
        }
        return {
          id: `openphish-${index}-${host}`,
          indicator: host,
          indicatorType: "url",
          malwareFamily: "N/A",
          threatType: "Phishing",
          firstSeen: fetchedAt,
          source: "OpenPhish",
        };
      });
  },
};
