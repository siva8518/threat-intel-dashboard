import { ApiError, fetchJson } from "../lib/http.js";

const HA_URL = "https://hybrid-analysis.com/api/v2/overview";
const SHA256_PATTERN = /^[0-9a-f]{64}$/i;

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

  const report = await fetchJson(`${HA_URL}/${value}`, {
    source: "Hybrid Analysis",
    headers: { "api-key": apiKey, "user-agent": "Falcon Sandbox" },
  });

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
