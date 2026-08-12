// Classifies a Hybrid Analysis request failure into one of the 7 buckets
// requested for this platform's Hybrid Analysis integration -- the direct
// fix for the reported problem that every failure (auth, quota, WAF block,
// timeout, genuine outage) rendered identically as a generic "Analysis
// Failed" with the raw upstream message, making it impossible to tell "my
// application is broken" apart from "DigitalOcean's network is blocked"
// apart from "Hybrid Analysis is down" without reading server logs by hand.
// Every classification is derived from real response data (status code,
// captured headers, body shape) already attached to the ApiError by
// server/lib/http.js's captureDiagnostics() -- never guessed from the
// error message string alone where structured data is available.
import { ApiError } from "../lib/http.js";

export const HA_FAILURE = {
  SUCCESS: "HYBRID_ANALYSIS_SUCCESS",
  RATE_LIMITED: "HYBRID_ANALYSIS_RATE_LIMITED",
  AUTH_FAILURE: "HYBRID_ANALYSIS_AUTH_FAILURE",
  NETWORK_ERROR: "HYBRID_ANALYSIS_NETWORK_ERROR",
  FORBIDDEN: "HYBRID_ANALYSIS_FORBIDDEN",
  TIMEOUT: "HYBRID_ANALYSIS_TIMEOUT",
  UNAVAILABLE: "HYBRID_ANALYSIS_UNAVAILABLE",
};

// A `server: cloudflare` (or Akamai/Fastly/CloudFront equivalent) header on
// a REJECTED response, especially paired with an HTML body instead of the
// JSON error shape Hybrid Analysis's own API returns for a real application-
// level rejection (see the confirmed-live `{"validation_errors": ...}` /
// `{"message": ...}` JSON shape), is the concrete, evidence-based signal
// that an edge/WAF layer rejected the request BEFORE it ever reached Hybrid
// Analysis's own application code -- as opposed to Hybrid Analysis's own
// API deliberately returning a 403 (which it does render as JSON).
function looksLikeEdgeOrWafBlock(diagnostics) {
  if (!diagnostics) return false;
  const server = (diagnostics.headers?.server ?? "").toLowerCase();
  const isEdgeVendor = /cloudflare|akamai|cloudfront|fastly|imperva|incapsula/.test(server);
  const contentType = (diagnostics.headers?.["content-type"] ?? "").toLowerCase();
  const bodyLooksLikeHtml = /^\s*</.test(diagnostics.bodySnippet ?? "") || contentType.includes("text/html");
  return isEdgeVendor && bodyLooksLikeHtml;
}

/**
 * @param {unknown} error
 * @returns {{ classification: string, isEdgeOrWafBlock: boolean, humanSummary: string }}
 */
export function classifyHybridAnalysisFailure(error) {
  if (!(error instanceof ApiError)) {
    return { classification: HA_FAILURE.UNAVAILABLE, isEdgeOrWafBlock: false, humanSummary: `Unexpected error: ${error?.message ?? String(error)}` };
  }

  if (error.status == null) {
    // No HTTP status at all -- either the request timed out client-side or
    // the connection never completed (DNS failure, connection refused, TLS
    // handshake failure). server/lib/http.js's request() produces these two
    // distinct message shapes; distinguish them rather than lumping both
    // under one generic "network error".
    if (/timed out after/i.test(error.message)) {
      return { classification: HA_FAILURE.TIMEOUT, isEdgeOrWafBlock: false, humanSummary: `Request to Hybrid Analysis timed out -- ${error.message}` };
    }
    return { classification: HA_FAILURE.NETWORK_ERROR, isEdgeOrWafBlock: false, humanSummary: `Could not reach Hybrid Analysis -- ${error.message}` };
  }

  const edgeBlock = looksLikeEdgeOrWafBlock(error.diagnostics);

  if (error.status === 401) {
    return { classification: HA_FAILURE.AUTH_FAILURE, isEdgeOrWafBlock: edgeBlock, humanSummary: "Hybrid Analysis rejected the API key (401) -- the key is missing, invalid, or revoked." };
  }
  if (error.status === 403) {
    return {
      classification: HA_FAILURE.FORBIDDEN,
      isEdgeOrWafBlock: edgeBlock,
      humanSummary: edgeBlock
        ? `Blocked before reaching Hybrid Analysis's application (403 from ${error.diagnostics?.headers?.server ?? "an edge/WAF layer"}) -- consistent with an IP/network-level block, not an application or API-key problem.`
        : "Hybrid Analysis returned 403 Forbidden from its own application (not an edge/WAF signature) -- check API key scope/permissions.",
    };
  }
  if (error.status === 429) {
    return { classification: HA_FAILURE.RATE_LIMITED, isEdgeOrWafBlock: edgeBlock, humanSummary: `Hybrid Analysis rate limit reached (429)${error.retryAfterMs ? ` -- retry after ${Math.ceil(error.retryAfterMs / 1000)}s` : ""}.` };
  }
  if (error.status >= 500) {
    return { classification: HA_FAILURE.UNAVAILABLE, isEdgeOrWafBlock: edgeBlock, humanSummary: `Hybrid Analysis reported a server-side error (${error.status}) -- likely a transient outage on their end.` };
  }
  return { classification: HA_FAILURE.UNAVAILABLE, isEdgeOrWafBlock: edgeBlock, humanSummary: `Hybrid Analysis responded with ${error.status} ${error.message}` };
}
