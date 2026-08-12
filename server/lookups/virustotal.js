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
  const attributes = data.data?.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;

  return {
    source: "VirusTotal",
    malicious,
    suspicious,
    harmless: stats.harmless ?? 0,
    verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "clean",
    // File-only metadata (ip/domain/url attributes have none of these) --
    // an analyst working a hash wants "what is this file and what does VT
    // call it" at least as much as the bare detection count, since the
    // count alone doesn't say whether it's a trojan, a stealer, ransomware,
    // etc. All optional/undefined for non-hash lookups, which is fine --
    // the frontend only renders whatever fields are actually present.
    fileType: attributes.type_description ?? null,
    fileName: attributes.meaningful_name ?? null,
    threatLabel: attributes.popular_threat_classification?.suggested_threat_label ?? null,
    firstSubmitted: attributes.first_submission_date ? new Date(attributes.first_submission_date * 1000).toISOString() : null,
    // IP/domain objects don't have first_submission_date (file-only, see
    // above), but do have last_analysis_date -- real, feeds the Timeline
    // sub-panel and firstLastSeenFor's lastSeen scan.
    lastSeen: attributes.last_analysis_date ? new Date(attributes.last_analysis_date * 1000).toISOString() : null,
    // File-only (undefined for ip/domain/url): VirusTotal computes and
    // stores MD5/SHA1/SHA256 for every file in its corpus, so a lookup by
    // any one of the three returns all three -- this is a real, provider-
    // reported association for the EXACT same file, never a mathematical
    // conversion between hash algorithms (which is impossible; hashes are
    // one-way). Used by hashModule.js for cross-hash enrichment: when a
    // provider that only accepts MD5/SHA1 (e.g. Team Cymru MHR) is given a
    // SHA256 IOC, the file's own MD5/SHA1 discovered here lets that
    // provider still be queried instead of being skipped as "not
    // applicable".
    relatedHashes: attributes.md5 || attributes.sha1 || attributes.sha256 ? { md5: attributes.md5 ?? null, sha1: attributes.sha1 ?? null, sha256: attributes.sha256 ?? null } : null,
  };
}
