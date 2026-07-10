import { ApiError, fetchJson } from "../lib/http.js";

const PULSEDIVE_BASE = "https://pulsedive.com/api";
const TYPE_MAP = { ip: "ip", domain: "domain", url: "url" };

function keyParam() {
  return process.env.PULSEDIVE_API_KEY ? `&key=${encodeURIComponent(process.env.PULSEDIVE_API_KEY)}` : "";
}

function toIso(stamp) {
  const iso = new Date(stamp.replace(" ", "T") + "Z");
  return Number.isNaN(iso.getTime()) ? new Date().toISOString() : iso.toISOString();
}

/**
 * Pulsedive's explore/info endpoints work keylessly (confirmed live against
 * the real API -- no auth required for either), though a free key from
 * pulsedive.com raises the modest anonymous rate limit, so it's added to the
 * query string when present but never required.
 */
export default {
  id: "pulsedive",
  label: "Pulsedive",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(`${PULSEDIVE_BASE}/explore.php?q=risk%3Dhigh&limit=100${keyParam()}`, { source: "Pulsedive" });

    return (data.results ?? [])
      .filter((entry) => TYPE_MAP[entry.type])
      .map((entry) => ({
        id: `pulsedive-${entry.iid}`,
        indicator: entry.indicator,
        indicatorType: TYPE_MAP[entry.type],
        malwareFamily: "Unknown",
        threatType: `Risk: ${entry.risk}`,
        firstSeen: entry.stamp_added ? toIso(entry.stamp_added) : new Date().toISOString(),
        source: "Pulsedive",
      }));
  },
};

/** On-demand single-indicator lookup for the IOC Search feature (ip/domain/url only -- Pulsedive has no file-hash support). */
export async function checkIndicator(type, value) {
  if (!TYPE_MAP[type]) throw new ApiError(`Pulsedive does not support looking up indicator type "${type}"`, "Pulsedive");

  const data = await fetchJson(`${PULSEDIVE_BASE}/info.php?indicator=${encodeURIComponent(value)}${keyParam()}`, { source: "Pulsedive" });
  const risk = data.risk ?? "unknown";

  return {
    source: "Pulsedive",
    risk,
    threats: (data.threats ?? []).map((t) => t.name),
    verdict: risk === "high" || risk === "critical" ? "malicious" : risk === "medium" || risk === "low" ? "suspicious" : "unknown",
  };
}
