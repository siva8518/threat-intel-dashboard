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
import { crossReferenceIndicator } from "./crossReference.js";

// Hoisted (not inlined in LOOKUPS below) so "Related Indicators" -- Same ASN
// (see gather()) can call it a second time, for a bounded set of sibling
// IPs, sharing the exact same 10-min cache/rate-limit state in
// lib/lookupLimiter.js rather than duplicating it.
const checkRipestatThrottled = throttleAndCache("RIPEstat", 1_000, checkRipestat);

const LOOKUPS = [
  checkOtx,
  checkAbuseIpdb,
  throttleAndCache("Pulsedive", 3_000, checkPulsedive),
  throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
  throttleAndCache("GreyNoise", 2_000, checkGreyNoise),
  throttleAndCache("Shodan", 1_000, checkShodan),
  throttleAndCache("LeakIX", 5_000, checkLeakix),
  checkRipestatThrottled,
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

  const relatedIndicators = await buildRelatedIndicators(value, network.asn);

  return {
    lookupResults: results,
    notConfigured,
    rateLimited,
    skipped,
    network,
    internalInvestigation,
    relatedIndicators,
    verdict: computeIocVerdict(results),
  };
}

/**
 * "Related Indicators" -- built entirely from indicators this app already
 * has on file (see server/investigation/crossReference.js#siblingIndicators),
 * not a fresh internet-wide search (no free source supports "list all IPs
 * on ASN X" or "list all IPs in this campaign" as a bulk query). Same ASN is
 * checked live against only this small sibling pool (capped at 5 RIPEstat
 * calls, already cached/throttled) -- not the whole threat feed, which would
 * mean hundreds of live lookups per search.
 */
async function buildRelatedIndicators(value, ownAsn) {
  const crossRef = crossReferenceIndicator(value);
  const siblings = crossRef.siblingIndicators;

  const sameCampaignOrActor = siblings.map((s) => ({
    indicator: s.indicator,
    indicatorType: s.indicatorType,
    malwareFamily: s.malwareFamily,
    associatedThreatActors: crossRef.associatedThreatActors,
    activeCampaigns: crossRef.activeCampaigns,
  }));

  const siblingIps = siblings.filter((s) => s.indicatorType === "ip").slice(0, 5);
  const sameAsn = [];
  if (ownAsn && siblingIps.length > 0) {
    const asnResults = await Promise.allSettled(siblingIps.map((s) => checkRipestatThrottled("ip", s.indicator)));
    for (let i = 0; i < siblingIps.length; i++) {
      const outcome = asnResults[i];
      if (outcome.status === "fulfilled" && outcome.value.asn && String(outcome.value.asn) === String(ownAsn)) {
        sameAsn.push({ indicator: siblingIps[i].indicator, asn: outcome.value.asn, holder: outcome.value.holder ?? null });
      }
    }
  }

  return { sameCampaignOrActor, sameAsn };
}
