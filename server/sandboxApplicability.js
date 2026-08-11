// IOC-type-aware "should this even be sandboxed" decision -- computed BEFORE
// any submission is offered to the analyst, and re-checked server-side
// before the submit route ever calls a provider (the frontend button being
// hidden is a UX nicety, not the actual guardrail). Every branch here maps
// directly to the platform's stated policy: never auto-submit every IOC,
// never sandbox a CVE or a bare IP directly, prefer analyzing a domain's
// known URLs over the domain itself, and be honest about the one type this
// platform genuinely cannot submit at all (raw files -- there is no file-
// upload flow anywhere in this app's text-based Investigation Workspace).
//
// Deliberately takes no dependency on sandboxIntelligence.js itself -- the
// caller (server/investigation/*.js per-type modules) already has the
// context this function needs (related URL candidates, IP report-overlap
// hits) computed once, so this stays a pure function over that context
// rather than re-querying the store itself.

/**
 * @param {"ip"|"domain"|"url"|"hash"|"cve"|string} type
 * @param {string} value
 * @param {{ relatedUrlCandidates?: string[], observedInSandboxReports?: { ip: string, jobId: string, provider: string }[] }} context
 * @returns {import("../src/types/threat-intel.js").SandboxApplicability}
 */
export function assessSandboxApplicability(type, value, context = {}) {
  if (type === "url") {
    return { applicable: true, recommendedAction: "submit", reason: "URLs are directly sandboxable -- checked against existing reports first, submitted only on explicit analyst request." };
  }

  if (type === "domain") {
    const candidates = context.relatedUrlCandidates ?? [];
    if (candidates.length > 0) {
      return {
        applicable: true,
        recommendedAction: "analyze_related_urls",
        reason: `${candidates.length} URL(s) on this domain are already known to this platform -- sandboxing those gives real execution/network evidence for actual observed paths, rather than guessing at what the bare domain's root page would do.`,
      };
    }
    return {
      applicable: true,
      recommendedAction: "submit",
      reason: "No known URLs on this domain in this platform's data -- the domain itself can be submitted, but a URL (if one becomes known) would be preferred.",
    };
  }

  if (type === "hash") {
    return {
      applicable: true,
      recommendedAction: "check_existing_only",
      reason: "A bare hash has no file bytes attached -- this platform can only check whether Hybrid Analysis already has a report for this exact hash, never submit new sandbox analysis for it.",
    };
  }

  if (type === "ip") {
    const hits = context.observedInSandboxReports ?? [];
    return {
      applicable: false,
      recommendedAction: hits.length > 0 ? "check_existing_only" : "not_applicable",
      reason:
        hits.length > 0
          ? `This IP is not sandboxed directly, but it appears as observed network activity in ${hits.length} existing sandbox report(s) already on file -- see Sandbox Analysis for those samples' behavior.`
          : "IPs are never submitted directly for sandbox analysis -- an IP is infrastructure, not a sample. This platform only surfaces sandbox evidence for an IP when it appears as observed network activity in a report already on file for a related URL/hash.",
    };
  }

  if (type === "cve") {
    return {
      applicable: false,
      recommendedAction: "not_applicable",
      reason: "A CVE identifier is never itself sandboxed -- there is no executable sample to run. If a related exploit sample, PoC download, or URL for this CVE is identified separately, search that indicator directly to check/submit sandbox analysis for it.",
    };
  }

  if (type === "file") {
    return {
      applicable: false,
      recommendedAction: "not_applicable",
      reason: "This platform's Investigation Workspace only accepts indicator values (hashes, URLs, domains, IPs, ...), not raw file uploads -- there is no file-submission flow here. If you have the sample, submit it directly at hybrid-analysis.com, then search its resulting hash in this platform.",
    };
  }

  return { applicable: false, recommendedAction: "not_applicable", reason: `Sandbox analysis does not apply to a ${type} indicator.` };
}
