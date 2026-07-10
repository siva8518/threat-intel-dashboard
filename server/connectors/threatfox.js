import { ApiError, fetchJson } from "../lib/http.js";
import { AbuseChAuthError, abuseChHeaders } from "../lib/abuseCh.js";

const THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/";

function toIsoDate(abuseChDate) {
  const iso = new Date(abuseChDate.replace(" ", "T").replace(" UTC", "Z"));
  return Number.isNaN(iso.getTime()) ? new Date().toISOString() : iso.toISOString();
}

function normalizeIocType(rawType) {
  if (rawType.startsWith("ip")) return "ip";
  if (rawType === "domain") return "domain";
  if (rawType === "url") return "url";
  if (rawType.endsWith("hash")) return "hash";
  return "unknown";
}

/** ThreatFox recent IOCs. Requires a free Auth-Key from https://auth.abuse.ch/. */
export default {
  id: "threatfox",
  label: "ThreatFox",
  intervalMs: 10 * 60 * 1000,
  async fetch() {
    let data;
    try {
      data = await fetchJson(THREATFOX_URL, {
        source: "ThreatFox",
        method: "POST",
        headers: abuseChHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ query: "get_iocs", days: 3 }),
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) throw new AbuseChAuthError("ThreatFox");
      throw error;
    }

    if (data.query_status !== "ok" || !data.data) {
      if (data.query_status === "no_result") return [];
      throw new AbuseChAuthError("ThreatFox");
    }

    return data.data.map((entry) => ({
      id: `threatfox-${entry.id}`,
      indicator: entry.ioc,
      indicatorType: normalizeIocType(entry.ioc_type),
      malwareFamily: entry.malware_printable || "Unknown",
      threatType: entry.threat_type,
      // Confirmed live: the field is `first_seen` (format "YYYY-MM-DD HH:MM:SS UTC",
      // same as URLHaus/MalwareBazaar) -- not `first_seen_utc`, which was undefined
      // on every entry and crashed this connector with a TypeError.
      firstSeen: toIsoDate(entry.first_seen),
      source: "ThreatFox",
    }));
  },
};
