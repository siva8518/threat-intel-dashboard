import { ApiError, fetchJson } from "../lib/http.js";
import { classifyHybridAnalysisFailure, HA_FAILURE } from "../sandbox/hybridAnalysisDiagnostics.js";
import { isCircuitOpen, circuitOpenRemainingMs, recordSandboxSuccess, recordSandboxFailure, recordSandboxNotFoundDiagnostic } from "../sandbox/sandboxProviderHealth.js";

const HA_URL = "https://hybrid-analysis.com/api/v2/overview";
const SHA256_PATTERN = /^[0-9a-f]{64}$/i;
const HEALTH_LABEL = "Hybrid Analysis";

/**
 * Hybrid Analysis (Falcon Sandbox) v2 API. Confirmed live with a real,
 * currently-issued API key that the old `/api/v2/search/hash` (POST)
 * endpoint now returns 410 Gone ("deprecated in API version 2.35.0 ... your
 * API key is newer than the deprecation date") -- a dummy key had earlier
 * given a misleadingly generic 403, masking this. The current live
 * replacement is `/api/v2/overview/{sha256}` (GET), confirmed live with a
 * real key -- but it only accepts SHA256 (the old endpoint took any hash
 * type), so MD5/SHA1 lookups now report a clear "unsupported" error instead
 * of a raw upstream validation failure.
 *
 * This is the single lowest-level choke point every Hybrid Analysis
 * hash-overview call goes through (server/sandbox/providers/
 * hybridAnalysisProvider.js#checkExistingHash and server/investigation/
 * hashModule.js both call this), so the circuit breaker + failure
 * classification live here once rather than being duplicated per caller.
 */
export async function checkIndicator(type, value) {
  if (type !== "hash") throw new ApiError("Hybrid Analysis only supports file hash lookups", "Hybrid Analysis");

  const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;
  if (!apiKey) {
    throw new ApiError(
      "Hybrid Analysis requires a free API key from hybrid-analysis.com (set HYBRID_ANALYSIS_API_KEY on the server)",
      "Hybrid Analysis",
      401,
    );
  }

  if (!SHA256_PATTERN.test(value)) {
    throw new ApiError("Hybrid Analysis only supports SHA256 hashes (not MD5/SHA1)", "Hybrid Analysis", 400);
  }

  // Circuit breaker: after enough consecutive network-level failures (see
  // sandboxProviderHealth.js), skip the real network round-trip entirely
  // and fail fast with a clearly-labeled, already-classified error instead
  // of repeating a call that has not succeeded in a while -- this is what
  // stops every single investigation search from re-attempting (and
  // burning quota on) a call that's very unlikely to succeed right now.
  if (isCircuitOpen(HEALTH_LABEL)) {
    const remainingSeconds = Math.ceil(circuitOpenRemainingMs(HEALTH_LABEL) / 1000);
    throw new ApiError(
      `Hybrid Analysis circuit breaker is open (repeated network-level failures) -- skipping this call, re-probing in ${remainingSeconds}s. See GET /api/dashboard/sandbox/health for diagnostics.`,
      "Hybrid Analysis",
      undefined,
      undefined,
      { classification: HA_FAILURE.UNAVAILABLE, circuitOpen: true },
    );
  }

  let report;
  try {
    report = await fetchJson(`${HA_URL}/${value}`, {
      source: "Hybrid Analysis",
      headers: { "api-key": apiKey, "user-agent": "Falcon Sandbox" },
    });
  } catch (error) {
    // A 404 ("no report exists for this hash") is a normal, expected
    // application-level outcome -- see hybridAnalysisProvider.js's own
    // "never throws for not found" contract -- not a health/availability
    // signal, so it's never recorded as a circuit-breaker failure.
    if (!(error instanceof ApiError) || error.status !== 404) {
      const classified = classifyHybridAnalysisFailure(error);
      recordSandboxFailure(HEALTH_LABEL, classified, { status: error?.status, headers: error?.diagnostics?.headers, bodySnippet: error?.diagnostics?.bodySnippet });
      // Attach the classification to the error so callers (routes/dashboard.js,
      // hybridAnalysisProvider.js) can persist it without re-deriving it.
      if (error instanceof ApiError) error.classification = classified.classification;
    } else {
      // Still capture the raw evidence for a 404 -- visible only via GET
      // /api/dashboard/sandbox/health, never affects the circuit breaker or
      // this call's normal "not found" behavior. Exists specifically to
      // distinguish a genuine "this hash has no report" 404 from a 404
      // that's actually masking something else (auth/network/WAF) for a
      // hash independently confirmed to exist.
      recordSandboxNotFoundDiagnostic(HEALTH_LABEL, { status: error.status, headers: error.diagnostics?.headers, bodySnippet: error.diagnostics?.bodySnippet });
    }
    throw error;
  }
  recordSandboxSuccess(HEALTH_LABEL);

  const score = report.threat_score ?? 0;
  const verdict =
    report.verdict === "malicious" || score >= 70
      ? "malicious"
      : report.verdict === "suspicious" || score >= 30
        ? "suspicious"
        : report.verdict === "whitelisted" || score === 0
          ? "clean"
          : "unknown";

  return {
    source: "Hybrid Analysis",
    verdictLabel: report.verdict ?? null,
    threatScore: score,
    malwareFamily: report.vx_family ?? null,
    verdict,
  };
}
