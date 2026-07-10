import { fetchJson } from "../lib/http.js";

const FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";

/** Feodo Tracker: active botnet C2 IPs. Free, no API key -- abuse.ch never gated this one. */
export default {
  id: "feodotracker",
  label: "Feodo Tracker",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(FEODO_URL, { source: "Feodo Tracker" });
    return data.map((entry) => ({
      id: `feodotracker-${entry.ip_address}-${entry.port}`,
      indicator: `${entry.ip_address}:${entry.port}`,
      indicatorType: "ip",
      malwareFamily: entry.malware || "Unknown",
      threatType: `Botnet C2 (${entry.status})`,
      firstSeen: new Date(entry.first_seen.replace(" ", "T") + "Z").toISOString(),
      source: "Feodo Tracker",
    }));
  },
};
