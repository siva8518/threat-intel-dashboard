// IP (v4/v6) investigation module -- Identity + Reputation sections reuse
// this app's existing on-demand IOC lookups verbatim (same fan-out the
// legacy /ioc-search route used for type "ip"); Network Intelligence adds
// reverse DNS (free, Node's own dns module) and OTX passive DNS (new, same
// already-configured OTX_API_KEY, no new integration); Internal Investigation
// is an explicit, honest "not connected" placeholder since this app has
// never integrated with any SIEM/firewall/proxy/NetFlow/VPN/EDR log source --
// rendering anything there would mean fabricating data.
import { checkIndicator as checkOtx, getPassiveDns } from "../connectors/otx.js";
import { checkIndicator as checkAbuseIpdb } from "../connectors/abuseipdb.js";
import { checkIndicator as checkPulsedive } from "../connectors/pulsedive.js";
import { checkIndicator as checkVirusTotal } from "../lookups/virustotal.js";
import { checkIndicator as checkGreyNoise } from "../lookups/greynoise.js";
import { checkIndicator as checkShodan } from "../lookups/shodan.js";
import { checkIndicator as checkLeakix } from "../lookups/leakix.js";
import { checkIndicator as checkRipestat } from "../lookups/ripestat.js";
import { checkIndicator as checkTeamCymru } from "../lookups/teamCymru.js";
import { checkIndicator as checkIsc } from "../lookups/isc.js";
import { throttleAndCache } from "../lib/lookupLimiter.js";
import { checkMispWarninglists } from "./mispCheck.js";
import { reverseDns } from "../lib/dnsRecords.js";
import { computeIocVerdict } from "./verdict.js";

const LOOKUPS = [
  checkOtx,
  checkAbuseIpdb,
  throttleAndCache("Pulsedive", 3_000, checkPulsedive),
  throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
  throttleAndCache("GreyNoise", 2_000, checkGreyNoise),
  throttleAndCache("Shodan", 1_000, checkShodan),
  throttleAndCache("LeakIX", 5_000, checkLeakix),
  throttleAndCache("RIPEstat", 1_000, checkRipestat),
  throttleAndCache("Team Cymru", 1_000, checkTeamCymru),
  throttleAndCache("SANS ISC", 2_000, checkIsc),
  checkMispWarninglists,
];

export const type = "ip";

export async function gather(value) {
  const settled = await Promise.allSettled(LOOKUPS.map((fn) => fn("ip", value)));
  const results = [];
  const notConfigured = [];
  const rateLimited = [];
  const skipped = [];
  for (const outcome of settled) {
    if (outcome.status === "fulfilled") results.push(outcome.value);
    else if (outcome.reason?.status === 401) notConfigured.push(outcome.reason.source);
    else if (outcome.reason?.status === 429) rateLimited.push(outcome.reason.source);
    else if (outcome.reason?.source) skipped.push({ source: outcome.reason.source, reason: outcome.reason.message ?? "Lookup failed" });
  }

  const [reverseHostname, passiveDnsResult] = await Promise.allSettled([reverseDns(value), getPassiveDns("ip", value)]);

  const find = (source) => results.find((r) => r.source === source);
  const shodan = find("Shodan");
  const ripestat = find("RIPEstat");
  const teamCymru = find("Team Cymru");
  const isc = find("SANS ISC");

  const network = {
    reverseDns: reverseHostname.status === "fulfilled" ? reverseHostname.value : null,
    passiveDns:
      passiveDnsResult.status === "fulfilled"
        ? { available: true, records: passiveDnsResult.value }
        : { available: false, reason: passiveDnsResult.reason?.status === 401 ? "OTX_API_KEY not configured" : (passiveDnsResult.reason?.message ?? "Lookup failed") },
    cidr: ripestat?.prefix ?? teamCymru?.prefix ?? null,
    asn: ripestat?.asn ?? teamCymru?.asn ?? isc?.asn ?? null,
    organization: shodan?.org ?? isc?.asName ?? ripestat?.holder ?? null,
    openPorts: Array.isArray(shodan?.openPorts) ? shodan.openPorts : [],
    country: find("AbuseIPDB")?.countryCode ?? isc?.country ?? teamCymru?.country ?? null,
  };

  const internalInvestigation = {
    connected: false,
    message:
      "Not Connected — this platform has no SIEM/log integration (Firewall, Proxy, DNS query logs, NetFlow, VPN, EDR). Configure a log source to surface internal sighting history here.",
  };

  return {
    lookupResults: results,
    notConfigured,
    rateLimited,
    skipped,
    network,
    internalInvestigation,
    verdict: computeIocVerdict(results),
  };
}
