import { ApiError, fetchJson } from "../lib/http.js";

const ISC_URL = "https://isc.sans.edu/api/ip";

/**
 * SANS Internet Storm Center / DShield IP lookup -- free, keyless. Confirmed
 * live against the real API and its own docs: "Currently, we do not require
 * authentication (we may in the future)." There is no API-key mechanism for
 * this read-only query endpoint at all (registered-account keys on
 * isc.sans.edu are for submitting honeypot/firewall logs, a different,
 * write-only use case, not for querying). The docs do ask for a descriptive
 * User-Agent (their default-UA requests get blocked) -- set below, no key
 * needed or used.
 *
 * Confirmed live: `count`/`attacks`/`maxdate`/`mindate` only populate for an
 * IP with very recent (last few days) honeypot-reported scanning activity --
 * most IPs, even ones ISC's own "top attackers" list ranks highly, show null
 * here since their activity is older. `threatfeeds` (which third-party
 * blocklists list this IP, with first/last-seen dates) is the more reliably
 * populated signal, so it drives the verdict rather than count/attacks alone.
 */
export async function checkIndicator(type, value) {
  if (type !== "ip") throw new ApiError("SANS ISC only supports IP lookups", "SANS ISC");

  const data = await fetchJson(`${ISC_URL}/${encodeURIComponent(value)}?json`, {
    source: "SANS ISC",
    headers: { "User-Agent": "threat-intel-dashboard (https://github.com/siva8518/threat-intel-dashboard)" },
  });
  const ip = data?.ip ?? {};
  const threatFeeds = Object.keys(ip.threatfeeds ?? {});
  const hasRecentActivity = ip.count != null || ip.attacks != null;

  const verdict = threatFeeds.length > 0 && hasRecentActivity ? "malicious" : threatFeeds.length > 0 || hasRecentActivity ? "suspicious" : "clean";

  return {
    source: "SANS ISC",
    verdict,
    reportCount: ip.count ?? null,
    attackTargets: ip.attacks ?? null,
    firstSeen: ip.mindate ?? null,
    lastSeen: ip.maxdate ?? null,
    asn: ip.as ?? null,
    asName: ip.asname ?? null,
    country: ip.ascountry ?? null,
    comment: ip.comment ?? null,
    threatFeeds,
  };
}
