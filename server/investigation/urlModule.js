// URL investigation module. Component parsing is pure `new URL()`; redirect
// chain/screenshot/HTML title/classification verdicts come from urlscan.io
// (the only free source that provides real ones) rather than this app
// inventing its own HTML-parsing heuristics for phishing/credential-
// harvesting/drive-by detection.
import { checkIndicator as checkOtx } from "../connectors/otx.js";
import { checkIndicator as checkPulsedive } from "../connectors/pulsedive.js";
import { checkIndicator as checkVirusTotal } from "../lookups/virustotal.js";
import { checkIndicator as checkUrlscan } from "../lookups/urlscan.js";
import { throttleAndCache } from "../lib/lookupLimiter.js";
import { checkMispWarninglists } from "./mispCheck.js";

const LOOKUPS = [checkOtx, throttleAndCache("Pulsedive", 3_000, checkPulsedive), throttleAndCache("VirusTotal", 15_000, checkVirusTotal), checkMispWarninglists];

function parseComponents(value) {
  try {
    const url = new URL(value);
    return {
      valid: true,
      protocol: url.protocol.replace(":", ""),
      host: url.hostname,
      port: url.port || (url.protocol === "https:" ? "443" : url.protocol === "http:" ? "80" : null),
      path: url.pathname,
      query: url.search ? Object.fromEntries(url.searchParams.entries()) : null,
      fragment: url.hash || null,
    };
  } catch {
    return { valid: false };
  }
}

export const type = "url";

export async function gather(value) {
  const settled = await Promise.allSettled([...LOOKUPS.map((fn) => fn("url", value)), checkUrlscan("url", value)]);
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

  const urlscan = results.find((r) => r.source === "urlscan.io") ?? null;

  return {
    lookupResults: results.filter((r) => r.source !== "urlscan.io"),
    notConfigured,
    rateLimited,
    skipped,
    components: parseComponents(value),
    scan: urlscan,
  };
}
