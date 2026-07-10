import { ApiError, fetchJson } from "../lib/http.js";

const RIPESTAT_URL = "https://stat.ripe.net/data";

/**
 * RIPEstat Data API -- free, keyless, no registration (RIPE NCC only asks
 * registration if you exceed ~1000 req/day, confirmed live via their own
 * docs). IP lookups only here: resolves an IP to its announcing ASN/prefix,
 * then that ASN to its WHOIS holder name, giving ASN/ownership context that
 * none of the other IOC Search sources provide.
 */
export async function checkIndicator(type, value) {
  if (type !== "ip") throw new ApiError("RIPEstat only supports IP lookups", "RIPEstat");

  const networkInfo = await fetchJson(`${RIPESTAT_URL}/network-info/data.json?resource=${encodeURIComponent(value)}`, { source: "RIPEstat" });
  const asns = networkInfo.data?.asns ?? [];
  const prefix = networkInfo.data?.prefix ?? null;

  let holder = null;
  if (asns.length > 0) {
    const overview = await fetchJson(`${RIPESTAT_URL}/as-overview/data.json?resource=AS${asns[0]}`, { source: "RIPEstat" });
    holder = overview.data?.holder ?? null;
  }

  return {
    source: "RIPEstat",
    verdict: "unknown", // informational -- ASN/ownership context, not a reputation verdict
    asn: asns[0] ?? null,
    prefix,
    holder,
  };
}
