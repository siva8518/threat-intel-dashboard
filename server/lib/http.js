const DEFAULT_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(message, source, status, retryAfterMs, diagnostics) {
    super(message);
    this.name = "ApiError";
    this.source = source;
    this.status = status;
    // Parsed from a 429/503's Retry-After header when present (seconds, or
    // an HTTP-date -- RFC 7231) -- undefined for every other error and for
    // any response that didn't send the header, so existing callers that
    // never look at this field are entirely unaffected.
    this.retryAfterMs = retryAfterMs;
    // Optional {headers: Record<string,string>, bodySnippet: string} --
    // present only when request() below captured it (see
    // DIAGNOSTIC_HEADER_ALLOWLIST). Every existing caller only ever reads
    // .message/.status/.retryAfterMs, so this is purely additive. Built for
    // distinguishing WAF/edge-level blocks (e.g. a `server: cloudflare` +
    // `cf-ray` 403 with an HTML challenge body) from an application-level
    // error (a JSON body with a real error message) without guessing --
    // see server/sandbox/hybridAnalysisDiagnostics.js, the first consumer.
    this.diagnostics = diagnostics;
  }
}

// A curated allowlist, not the full header set -- avoids ever capturing
// something that could carry a session/auth-adjacent value, while keeping
// every header actually useful for telling "this app rejected the request"
// apart from "an edge/WAF in front of the app rejected it first" (the
// specific ambiguity behind the reported Hybrid Analysis 403).
const DIAGNOSTIC_HEADER_ALLOWLIST = ["server", "via", "cf-ray", "cf-mitigated", "cf-cache-status", "x-cache", "x-amz-cf-id", "x-amz-cf-pop", "x-served-by", "x-akamai-request-id", "retry-after", "content-type", "date"];
const DIAGNOSTIC_BODY_SNIPPET_MAX_CHARS = 500;

async function captureDiagnostics(response) {
  try {
    const headers = {};
    for (const name of DIAGNOSTIC_HEADER_ALLOWLIST) {
      const value = response.headers.get(name);
      if (value) headers[name] = value;
    }
    const bodySnippet = (await response.clone().text()).slice(0, DIAGNOSTIC_BODY_SNIPPET_MAX_CHARS);
    return { headers, bodySnippet };
  } catch {
    return { headers: {}, bodySnippet: "" }; // never let diagnostic capture itself break the real error path
  }
}

function parseRetryAfterMs(response) {
  const header = response.headers.get("retry-after");
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const dateMs = Date.parse(header);
  return Number.isFinite(dateMs) ? Math.max(0, dateMs - Date.now()) : undefined;
}

async function request(url, { source, timeoutMs = DEFAULT_TIMEOUT_MS, ...init }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      const diagnostics = await captureDiagnostics(response);
      throw new ApiError(`${source} responded with ${response.status} ${response.statusText}`, source, response.status, parseRetryAfterMs(response), diagnostics);
    }
    return response;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === "AbortError") throw new ApiError(`${source} timed out after ${timeoutMs}ms`, source);
    throw new ApiError(`${source} is unreachable: ${error.message}`, source);
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchJson(url, options) {
  const response = await request(url, options);
  // A 204 has no body -- response.json() would throw trying to parse an
  // empty string (confirmed live: LeakIX returns 204, not 200 + `[]`/`{}`,
  // for a query with zero results). No other connector in this app currently
  // triggers a 204, so this is a safe, backward-compatible addition.
  if (response.status === 204) return null;
  return response.json();
}

export async function fetchText(url, options) {
  const response = await request(url, options);
  return response.text();
}
