import { fetchText } from "../lib/http.js";

const ET_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt";

/** Proofpoint Emerging Threats compromised-host IP blocklist. Free, no API key, plain text one-IP-per-line (confirmed live). */
export default {
  id: "emerging-threats",
  label: "Emerging Threats (Proofpoint)",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const text = await fetchText(ET_URL, { source: "Emerging Threats" });
    const fetchedAt = new Date().toISOString();

    return text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .map((ip) => ({
        id: `emerging-threats-${ip}`,
        indicator: ip,
        indicatorType: "ip",
        malwareFamily: "Unknown",
        threatType: "Compromised host",
        firstSeen: fetchedAt,
        source: "Emerging Threats",
      }));
  },
};
