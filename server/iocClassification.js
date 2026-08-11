// Benign-infrastructure / malicious classification for the canonical IOC
// store (server/iocIntelligence.js). Confirmed gap this closes: nothing
// anywhere in this app previously distinguished "this IP/domain was reported
// as attacker-controlled infrastructure" from "this IP/domain merely appears
// in a vendor report because Cloudflare/a CDN/a documentation site happened
// to be mentioned" -- every extracted candidate was treated identically. A
// report naming Cloudflare's own edge IP (because the malicious site sits
// behind it, or because the article's own screenshot shows an unrelated
// address) must not silently become a "malicious IOC" just by appearing in
// threat-intel prose.
//
// Two signals, no network I/O in the hot path (classification runs against
// every extraction candidate, at extraction-time volume -- a live WHOIS/ASN
// call per candidate is not viable at that scale):
//   1. A small, hand-maintained, stable set of Cloudflare's own published
//      edge-network CIDR ranges (their edge network is genuinely small and
//      rarely changes, unlike AWS/GCP/Azure's thousands of non-contiguous
//      blocks -- deliberately NOT attempting to hardcode those larger
//      providers' ranges here, since an incomplete/stale guess at their
//      scale would be actively misleading; server/iocIntelligence.js's
//      lazy RIPEstat ASN-holder lookup covers those instead, see
//      enrichIndicatorAsn below).
//   2. Keyword-context heuristics on the sentence surrounding the match --
//      "hosted on a compromised", "abused legitimate", "sinkholed" flip a
//      hit toward infrastructure/benign; "C2", "command and control",
//      "delivers the payload", "distributes" reinforce malicious.
// Same "documented heuristic, not a black box" philosophy as
// server/githubIntel/extractor.js's own REFERENCE_DOMAIN_EXCLUSIONS list,
// which this module also reuses and extends.
import { checkIndicator as checkRipestat } from "./lookups/ripestat.js";
import { log } from "./lib/log.js";

// Cloudflare's own published edge-network IPv4 ranges (cloudflare.com/ips) --
// small, stable, well-documented. Not exhaustive of every CDN/cloud
// provider (see module comment above); extend this list only with ranges
// this confident-and-stable, never a guess.
const CLOUDFLARE_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
];

// Well-known public DNS resolvers -- single, extremely stable anycast IPs
// that show up constantly in threat-intel prose purely as DNS
// configuration/testing references, never as attacker infrastructure.
const KNOWN_RESOLVER_IPS = new Set(["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"]);

function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipInCidr(ip, cidr) {
  const [rangeIp, bitsStr] = cidr.split("/");
  const ipInt = ipToInt(ip);
  const rangeInt = ipToInt(rangeIp);
  if (ipInt === null || rangeInt === null) return false;
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

function isCloudflareIp(ip) {
  return CLOUDFLARE_CIDRS.some((cidr) => ipInCidr(ip, cidr));
}

const MALICIOUS_CONTEXT_KEYWORDS = /\b(c2|command[- ]and[- ]control|delivers?\s+the\s+payload|distributes?\s+the\s+malware|drops?\s+(a|the)\s+payload|downloads?\s+(a|the)\s+(payload|malware)|phishing\s+(domain|site|page)|exfiltrat(e|es|ed|ion)|malicious\s+(domain|ip|infrastructure|payload)|attacker[- ]controlled|beacon(s|ing)?\s+to)\b/i;
const BENIGN_CONTEXT_KEYWORDS = /\b(hosted\s+on\s+a\s+compromised|abused\s+(a\s+)?legitimate|sinkhole(d|s)?|legitimate\s+service\s+abused|was\s+compromised\s+to\s+host|reference|documentation|see\s+(the\s+)?advisory)\b/i;

// Categories the canonical store persists per record. `unknown` is the
// honest fallback when neither signal fires -- never defaulted to
// "malicious_observed" just because a regex matched something.
const CLASSIFICATIONS = {
  MALICIOUS: "malicious_observed",
  INFRASTRUCTURE: "infrastructure_context",
  BENIGN: "benign_reference",
  UNKNOWN: "unknown",
};
export { CLASSIFICATIONS };

/**
 * @param {string} type - canonical type from iocIntelligence.js (e.g. "ipv4", "domain", "sha256")
 * @param {string} value - normalized indicator value
 * @param {string|null} contextSnippet - text surrounding the match in its source article, if available
 * @returns {{classification: string, reason: string, confidence: "High"|"Medium"|"Low"}}
 */
export function classifyIndicator(type, value, contextSnippet) {
  const snippet = contextSnippet ?? "";

  if (type === "ipv4") {
    if (KNOWN_RESOLVER_IPS.has(value)) {
      return { classification: CLASSIFICATIONS.INFRASTRUCTURE, reason: "Known public DNS resolver IP, not attacker infrastructure.", confidence: "High" };
    }
    if (isCloudflareIp(value)) {
      return { classification: CLASSIFICATIONS.INFRASTRUCTURE, reason: "Cloudflare edge-network IP -- ownership of shared infrastructure is context, not evidence of malicious use.", confidence: "High" };
    }
  }

  // File hashes, CVE IDs, and other non-network observables have no
  // plausible "benign infrastructure" reading -- a real SHA256/CVE match is
  // either a genuine observable or a false-positive regex match (already
  // filtered upstream by extractor.js's own precision-oriented patterns),
  // never "someone else's shared infrastructure."
  if (["sha256", "sha1", "md5", "cve"].includes(type)) {
    return { classification: CLASSIFICATIONS.MALICIOUS, reason: "Extracted file hash or CVE identifier -- no infrastructure-sharing ambiguity applies to this type.", confidence: "Medium" };
  }

  if (BENIGN_CONTEXT_KEYWORDS.test(snippet)) {
    return { classification: CLASSIFICATIONS.INFRASTRUCTURE, reason: "Surrounding article text indicates this was legitimate/compromised infrastructure, not attacker-owned.", confidence: "Medium" };
  }
  if (MALICIOUS_CONTEXT_KEYWORDS.test(snippet)) {
    return { classification: CLASSIFICATIONS.MALICIOUS, reason: "Surrounding article text explicitly describes malicious use (C2/payload delivery/exfiltration/phishing).", confidence: "Medium" };
  }

  // No strong signal either way -- honestly unknown rather than defaulted to
  // malicious. This is the single most important line in this file: the
  // whole point of this module is that a bare regex match is NOT, by
  // itself, evidence of malicious activity.
  return { classification: CLASSIFICATIONS.UNKNOWN, reason: "No infrastructure-ownership or malicious-use signal found in the surrounding text -- observed, not yet classified.", confidence: "Low" };
}

/**
 * Extracts up to `windowChars` characters of text on each side of `value`'s
 * first occurrence in `fullText` -- the "context snippet" classifyIndicator's
 * keyword heuristics run against, and the same snippet persisted on the
 * canonical record for analyst review (requirement: every IOC retains a
 * context snippet, not just a bare value).
 */
export function extractContextSnippet(fullText, value, windowChars = 120) {
  if (!fullText || !value) return null;
  const idx = fullText.indexOf(value);
  if (idx === -1) return null;
  const start = Math.max(0, idx - windowChars);
  const end = Math.min(fullText.length, idx + value.length + windowChars);
  return fullText.slice(start, end).replace(/\s+/g, " ").trim();
}

// Lazy ASN-holder enrichment for IPs the static classifier left `unknown` on
// -- reserved for a slow, capped cadence (see server/iocExtractionJob.js's
// own per-cycle cap), never run at full extraction volume. Result is cached
// indefinitely on the canonical record once computed (an ASN doesn't change
// hour to hour), so this cost is paid at most once per unique IP, not once
// per sighting.
const KNOWN_HYPERSCALER_HOLDER_KEYWORDS = /\b(AMAZON|GOOGLE|MICROSOFT|AKAMAI|FASTLY|CLOUDFLARE|ORACLE\s+CLOUD|DIGITALOCEAN|OVH|LINODE|HETZNER)\b/i;

export async function enrichIndicatorAsn(ip) {
  try {
    const result = await checkRipestat("ip", ip);
    const holder = result.holder ?? null;
    const isHyperscaler = holder ? KNOWN_HYPERSCALER_HOLDER_KEYWORDS.test(holder) : false;
    return { asn: result.asn ?? null, asnHolder: holder, isHyperscaler, enrichedAt: new Date().toISOString() };
  } catch (error) {
    log.warn("ioc-classification", `RIPEstat enrichment failed for ${ip}: ${error.message}`);
    return null;
  }
}
