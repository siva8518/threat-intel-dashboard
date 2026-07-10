import { fetchText } from "../lib/http.js";

const SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt";

/**
 * Spamhaus DROP (Don't Route Or Peer) list of hijacked/malicious netblocks.
 * Free, no API key, plain text CIDR list. EDROP was merged into DROP --
 * confirmed live: edrop.txt now just contains a note pointing back to
 * drop.txt, so that file is skipped entirely rather than fetched for nothing.
 */
export default {
  id: "spamhaus",
  label: "Spamhaus DROP",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const text = await fetchText(SPAMHAUS_DROP_URL, { source: "Spamhaus DROP" });
    const fetchedAt = new Date().toISOString();

    return text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith(";"))
      .map((line) => {
        const [cidr, sbl] = line.split(";").map((part) => part.trim());
        return {
          id: `spamhaus-${cidr}`,
          indicator: cidr,
          indicatorType: "ip",
          malwareFamily: "Unknown",
          threatType: sbl ? `Hijacked/malicious netblock (${sbl})` : "Hijacked/malicious netblock",
          firstSeen: fetchedAt,
          source: "Spamhaus DROP",
        };
      });
  },
};
