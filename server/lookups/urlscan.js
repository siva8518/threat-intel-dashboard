// urlscan.io -- the only free source that actually provides a real
// screenshot, redirect chain, and rendered page title for a URL. Search over
// already-scanned URLs is free and keyless; submitting a fresh scan needs
// URLSCAN_API_KEY (small free allowance) and is only attempted when a key is
// configured, so this degrades to "no scan available" rather than failing
// when unconfigured -- searching still works either way.
import { ApiError, fetchJson } from "../lib/http.js";
import { withRetry } from "../lib/retry.js";

const API_KEY = process.env.URLSCAN_API_KEY;

function mapResult(result) {
  const page = result.page ?? {};
  const task = result.task ?? {};
  const verdicts = result.verdicts?.overall ?? {};
  return {
    scanId: task.uuid ?? null,
    scanUrl: task.uuid ? `https://urlscan.io/result/${task.uuid}/` : null,
    screenshotUrl: task.uuid ? `https://urlscan.io/screenshots/${task.uuid}.png` : null,
    finalUrl: page.url ?? null,
    pageTitle: page.title ?? null,
    ipAddress: page.ip ?? null,
    country: page.country ?? null,
    server: page.server ?? null,
    malicious: verdicts.malicious ?? false,
    score: verdicts.score ?? null,
    categories: verdicts.categories ?? [],
    tags: verdicts.tags ?? [],
    scannedAt: task.time ?? null,
  };
}

/**
 * Searches urlscan.io for an existing public scan of this exact URL --
 * keyless, no submission. Returns the most recent scan, or null if this URL
 * has never been scanned by anyone before.
 */
async function searchExisting(url) {
  const query = `page.url:"${url}"`;
  const data = await withRetry(
    () => fetchJson(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=1`, { source: "urlscan.io", timeoutMs: 10_000 }),
    { retries: 1, baseDelayMs: 500 },
  );
  const hit = data?.results?.[0];
  return hit ? mapResult(hit) : null;
}

/** Submits a fresh scan and polls briefly for the result -- only attempted when URLSCAN_API_KEY is configured. */
async function submitScan(url) {
  const submission = await fetchJson("https://urlscan.io/api/v1/scan/", {
    source: "urlscan.io",
    method: "POST",
    headers: { "API-Key": API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify({ url, visibility: "unlisted" }),
    timeoutMs: 10_000,
  });

  // Scans typically finish in 10-20s; poll a few times rather than blocking
  // the whole investigation request on a full scan cycle.
  for (let attempt = 0; attempt < 4; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 5_000));
    try {
      const result = await fetchJson(`https://urlscan.io/api/v1/result/${submission.uuid}/`, { source: "urlscan.io", timeoutMs: 8_000 });
      return mapResult({ page: result.page, task: result.task, verdicts: result.verdicts });
    } catch {
      // Not ready yet -- keep polling until the attempt budget runs out.
    }
  }
  return null;
}

export async function checkIndicator(type, value) {
  if (type !== "url") throw new ApiError("urlscan.io only supports URL lookups", "urlscan.io");

  const existing = await searchExisting(value);
  if (existing) return { source: "urlscan.io", verdict: existing.malicious ? "malicious" : "unknown", ...existing, submitted: false };

  if (!API_KEY) {
    return { source: "urlscan.io", verdict: "unknown", scanId: null, notScanned: true, reason: "No prior public scan exists, and URLSCAN_API_KEY is not configured to submit a new one." };
  }

  const submitted = await submitScan(value);
  if (!submitted) {
    return { source: "urlscan.io", verdict: "unknown", scanId: null, notScanned: true, reason: "Scan submitted but did not complete in time -- check urlscan.io directly." };
  }
  return { source: "urlscan.io", verdict: submitted.malicious ? "malicious" : "unknown", ...submitted, submitted: true };
}
