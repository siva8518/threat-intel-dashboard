import { ApiError, fetchJson } from "../lib/http.js";

const SHODAN_URL = "https://api.shodan.io/shodan/host";

/**
 * Shodan's free tier is IP-only host lookups (no domain/hash/url, no bulk
 * feed) -- on-demand only, called live from the IOC Search route. Treated as
 * the lowest-priority optional source since the free tier is the most
 * limited of the five.
 */
export async function checkIndicator(type, value) {
  if (type !== "ip") throw new ApiError("Shodan only supports IP lookups", "Shodan");

  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) {
    throw new ApiError("Shodan requires a free API key from shodan.io (set SHODAN_API_KEY on the server)", "Shodan", 401);
  }

  const data = await fetchJson(`${SHODAN_URL}/${value}?key=${encodeURIComponent(apiKey)}`, { source: "Shodan" });
  const vulnCount = data.vulns ? Object.keys(data.vulns).length : 0;

  return {
    source: "Shodan",
    org: data.org ?? null,
    openPorts: data.ports ?? [],
    vulnCount,
    tags: data.tags ?? [],
    verdict: vulnCount > 0 ? "suspicious" : "unknown",
  };
}
