import { ApiError, fetchJson } from "../lib/http.js";

const VT_BASE = "https://www.virustotal.com/api/v3";

/**
 * VirusTotal's free API tier is rate-limited (4 req/min, 500/day) and only
 * supports looking up ONE indicator at a time -- there's no free bulk "recent
 * threats" feed, so this is on-demand only, called live from the IOC Search
 * route, never scheduled/cached in bulk.
 */
export async function checkIndicator(type, value) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    throw new ApiError("VirusTotal requires a free API key from virustotal.com (set VIRUSTOTAL_API_KEY on the server)", "VirusTotal", 401);
  }

  const path = {
    ip: `ip_addresses/${value}`,
    domain: `domains/${value}`,
    hash: `files/${value}`,
    url: `urls/${Buffer.from(value).toString("base64url")}`,
  }[type];
  if (!path) throw new ApiError(`VirusTotal does not support looking up indicator type "${type}"`, "VirusTotal");

  const data = await fetchJson(`${VT_BASE}/${path}`, { source: "VirusTotal", headers: { "x-apikey": apiKey } });
  const stats = data.data?.attributes?.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;

  return {
    source: "VirusTotal",
    malicious,
    suspicious,
    harmless: stats.harmless ?? 0,
    verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean",
  };
}
