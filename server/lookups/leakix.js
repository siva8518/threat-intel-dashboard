import { ApiError, fetchJson } from "../lib/http.js";

const LEAKIX_BASE = "https://leakix.net";
const MAX_SAMPLES = 5;

function authHeaders() {
  const key = process.env.LEAKIX_API_KEY;
  if (!key) return null;
  return { "api-key": key, Accept: "application/json" };
}

/**
 * LeakIX: free (registered-key) OSINT search for exposed services and leaked
 * data tied to a domain/IP -- IP and domain only, no url/hash support.
 * Confirmed live: `/host/{ip}` can return hundreds of service records for a
 * busy/shared IP (600 for 8.8.8.8 alone), so this summarizes (counts + a few
 * samples) rather than returning the raw blob. A query with zero results
 * returns 204 (handled by fetchJson -- see server/lib/http.js), not 200+[].
 */
export async function checkIndicator(type, value) {
  if (type !== "ip" && type !== "domain") throw new ApiError("LeakIX only supports IP and domain lookups", "LeakIX");

  const headers = authHeaders();
  if (!headers) {
    throw new ApiError("LeakIX requires a free API key from leakix.net (set LEAKIX_API_KEY on the server)", "LeakIX", 401);
  }

  let services = [];
  let leaks = [];

  if (type === "ip") {
    const data = await fetchJson(`${LEAKIX_BASE}/host/${encodeURIComponent(value)}`, { source: "LeakIX", headers });
    services = data?.Services ?? [];
    leaks = data?.Leaks ?? [];
  } else {
    const [serviceResults, leakResults] = await Promise.all([
      fetchJson(`${LEAKIX_BASE}/search?scope=service&q=${encodeURIComponent(value)}`, { source: "LeakIX", headers }),
      fetchJson(`${LEAKIX_BASE}/search?scope=leak&q=${encodeURIComponent(value)}`, { source: "LeakIX", headers }),
    ]);
    services = serviceResults ?? [];
    leaks = leakResults ?? [];
  }

  return {
    source: "LeakIX",
    serviceCount: services.length,
    leakCount: leaks.length,
    sampleServices: services.slice(0, MAX_SAMPLES).map((s) => ({
      host: s.host,
      port: s.port,
      protocol: s.protocol,
      title: s.http?.title ?? null,
    })),
    sampleLeaks: leaks.slice(0, MAX_SAMPLES).map((l) => ({
      host: l.host,
      summary: (l.summary ?? "").slice(0, 200),
    })),
    verdict: leaks.length > 0 ? "malicious" : services.length > 0 ? "suspicious" : "unknown",
  };
}
