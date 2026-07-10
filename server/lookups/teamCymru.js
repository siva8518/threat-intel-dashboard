import { Resolver } from "node:dns/promises";
import { ApiError } from "../lib/http.js";

const LOOKUP_TIMEOUT_MS = 8_000;

// Uses an explicit public resolver instead of the OS's configured DNS
// server(s) (dns.resolveTxt's default). Confirmed live this matters: on a
// machine whose system resolver is a local proxy (127.0.0.1, e.g. from a VPN
// or security suite) that only handles normal browser DNS and refuses raw
// TXT queries, plain dns.resolveTxt() fails with ECONNREFUSED even though
// the DNS zone itself is fine -- pointing at Google/Cloudflare's public
// resolvers directly sidesteps that class of local-network misconfiguration.
const resolver = new Resolver();
resolver.setServers(["8.8.8.8", "1.1.1.1"]);

// Team Cymru's IP-to-ASN and Malware Hash Registry services are DNS zones,
// not REST APIs -- free, keyless, no registration (non-commercial use, per
// their own docs). Confirmed live via direct `nslookup -type=TXT`:
// "8.8.8.8.origin.asn.cymru.com" -> "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
// and "AS15169.asn.cymru.com" -> "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US".
// The Malware Hash Registry format ("{md5|sha1}.malware.hash.cymru.com" ->
// "<lastseen_epoch> <detection_pct>", NXDOMAIN if unknown) is Team Cymru's
// own long-documented, stable format -- confirmed the zone itself resolves
// correctly (NXDOMAIN for a known-benign test hash), but a live malicious
// hit wasn't available to test against without a hash on hand.
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("Team Cymru DNS lookup timed out")), ms)),
  ]);
}

async function txtLookup(hostname) {
  try {
    const records = await withTimeout(resolver.resolveTxt(hostname), LOOKUP_TIMEOUT_MS);
    return records[0]?.join("") ?? null;
  } catch (error) {
    if (error.code === "ENOTFOUND" || error.code === "ENODATA") return null; // not in the registry -- routine, not a failure
    throw new ApiError(`Team Cymru DNS lookup failed: ${error.message}`, "Team Cymru");
  }
}

async function checkIp(value) {
  const answer = await txtLookup(`${value}.origin.asn.cymru.com`);
  if (!answer) return { source: "Team Cymru", verdict: "unknown", asn: null, prefix: null, country: null, registry: null };

  const [asn, prefix, country, registry, allocated] = answer.split("|").map((s) => s.trim());
  return { source: "Team Cymru", verdict: "unknown", asn, prefix, country, registry, allocated };
}

async function checkHash(value) {
  const answer = await txtLookup(`${value.toLowerCase()}.malware.hash.cymru.com`);
  if (!answer) return { source: "Team Cymru MHR", verdict: "unknown", note: "Not found in Malware Hash Registry" };

  const [lastSeenEpoch, detectionPercent] = answer.trim().split(/\s+/);
  return {
    source: "Team Cymru MHR",
    verdict: Number(detectionPercent) > 0 ? "malicious" : "unknown",
    lastSeen: lastSeenEpoch ? new Date(Number(lastSeenEpoch) * 1000).toISOString() : null,
    detectionPercent: detectionPercent ? Number(detectionPercent) : null,
  };
}

export async function checkIndicator(type, value) {
  if (type === "ip") return checkIp(value);
  if (type === "hash") return checkHash(value);
  throw new ApiError("Team Cymru only supports IP and hash lookups", "Team Cymru");
}
