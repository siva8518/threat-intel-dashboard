import { ApiError, fetchJson } from "../lib/http.js";
import { withRetry } from "../lib/retry.js";

const CRTSH_URL = "https://crt.sh/";

/**
 * Certificate Transparency log search -- free, keyless, no registration.
 * Domain lookups only (crt.sh has no IP/hash/url search). Confirmed live
 * that crt.sh is occasionally slow/flaky (intermittent 404/502 under load),
 * so this is wrapped in a retry rather than failing on the first hiccup,
 * same pattern as the bulk connectors use via withRetry.
 *
 * Kept deliberately tight (was 20s x 3 attempts, a ~63s worst case) --
 * confirmed live this single source, run in parallel with every other
 * domain lookup via Promise.allSettled in the /ioc-search route, was
 * dominating the wait for the *entire* domain search when crt.sh was slow,
 * making a fresh Triage Console query look like it returned nothing at all
 * (it was still loading, just far past what anyone would wait for). This
 * source is explicitly informational only (see verdict below), not worth
 * holding up every other, faster-responding source for.
 */
export async function checkIndicator(type, value) {
  if (type !== "domain") throw new ApiError("crt.sh only supports domain lookups", "crt.sh");

  const data = await withRetry(
    () => fetchJson(`${CRTSH_URL}?q=${encodeURIComponent(value)}&output=json`, { source: "crt.sh", timeoutMs: 8_000 }),
    { retries: 1, baseDelayMs: 500 },
  );

  const entries = Array.isArray(data) ? data : [];
  const subdomains = new Set();
  let latestIssuer = null;
  let latestNotBefore = null;

  for (const entry of entries) {
    for (const name of (entry.name_value ?? "").split("\n")) {
      const trimmed = name.trim().toLowerCase();
      if (trimmed) subdomains.add(trimmed);
    }
    if (!latestNotBefore || new Date(entry.not_before) > new Date(latestNotBefore)) {
      latestNotBefore = entry.not_before;
      latestIssuer = entry.issuer_name;
    }
  }

  return {
    source: "crt.sh",
    verdict: "unknown", // informational only -- certificate transparency doesn't imply malicious/clean
    certificateCount: entries.length,
    subdomainCount: subdomains.size,
    subdomains: Array.from(subdomains).slice(0, 25),
    latestIssuer,
    latestNotBefore,
  };
}
