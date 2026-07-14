import { isIP } from "node:net";
import { ApiError, fetchJson } from "../lib/http.js";
import { AbuseChAuthError, abuseChHeaders } from "../lib/abuseCh.js";

const URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/";

function toIsoDate(abuseChDate) {
  const iso = new Date(abuseChDate.replace(" ", "T").replace(" UTC", "Z"));
  return Number.isNaN(iso.getTime()) ? new Date().toISOString() : iso.toISOString();
}

/**
 * URLHaus recent malicious URLs. Requires the same free Auth-Key as
 * ThreatFox/MalwareBazaar (abuse.ch unified auth) -- confirmed live that
 * URLHaus is no longer keyless, contrary to its older docs. Also confirmed
 * live: this endpoint now expects GET, not POST (POST returns 405 with
 * query_status "http_get_expected") -- another abuse.ch API change that
 * only surfaced once a real Auth-Key was configured to test against.
 */
export default {
  id: "urlhaus",
  label: "URLHaus",
  intervalMs: 10 * 60 * 1000,
  async fetch() {
    let data;
    try {
      data = await fetchJson(URLHAUS_URL, {
        source: "URLHaus",
        method: "GET",
        headers: abuseChHeaders(),
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) throw new AbuseChAuthError("URLHaus");
      throw error;
    }

    if (data.query_status !== "ok" || !data.urls) return [];

    return data.urls.map((entry) => ({
      id: `urlhaus-${entry.id}`,
      // `host` is the extracted host portion of the malicious URL -- can be
      // a real domain OR a bare IP (e.g. "http://183.92.205.84/mirai.arm7"),
      // confirmed live via a Mirai sample tagged "domain" for a plain IPv4
      // address. isIP() disambiguates instead of assuming "any host = domain".
      indicator: entry.host || entry.url,
      indicatorType: entry.host ? (isIP(entry.host) ? "ip" : "domain") : "url",
      malwareFamily: entry.tags?.length ? entry.tags.join(", ") : "Unknown",
      threatType: entry.threat || "malware_download",
      firstSeen: toIsoDate(entry.date_added),
      source: "URLHaus",
    }));
  },
};
