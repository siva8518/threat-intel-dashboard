import { ApiError, fetchJson } from "../lib/http.js";

class PhishTankNotConfiguredError extends ApiError {
  constructor() {
    super(
      "PhishTank requires a free registered API key from phishtank.org (set PHISHTANK_API_KEY on the server) -- confirmed live that anonymous bulk downloads are now capped at 75 requests/3 days and routed through a CDN that 404s without one",
      "PhishTank",
      401,
    );
  }
}

/** PhishTank verified-phishing-URL bulk feed. */
export default {
  id: "phishtank",
  label: "PhishTank",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const apiKey = process.env.PHISHTANK_API_KEY;
    if (!apiKey) throw new PhishTankNotConfiguredError();

    let data;
    try {
      data = await fetchJson(`https://data.phishtank.com/data/${apiKey}/online-valid.json`, {
        source: "PhishTank",
        headers: { "User-Agent": "phishtank/threat-intel-dashboard" },
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) throw new PhishTankNotConfiguredError();
      throw error;
    }

    return (data ?? []).slice(0, 200).map((entry) => {
      let host = entry.url;
      try {
        host = new URL(entry.url).host;
      } catch {
        // leave host as the raw string if it isn't a valid URL
      }
      return {
        id: `phishtank-${entry.phish_id}`,
        indicator: host,
        indicatorType: "url",
        malwareFamily: "N/A",
        threatType: "Phishing",
        firstSeen: entry.submission_time ? new Date(entry.submission_time).toISOString() : new Date().toISOString(),
        source: "PhishTank",
      };
    });
  },
};
