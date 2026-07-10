import { ApiError } from "./http.js";

// On-demand lookups are re-searched often for the same indicator; a short
// cache means repeat searches are free instead of burning free-tier quota.
const CACHE_TTL_MS = 10 * 60 * 1000;
const cache = new Map(); // `${source}:${type}:${value}` -> { result, cachedAt }
const lastCallAt = new Map(); // source -> timestamp of its last live call

/**
 * Wraps an on-demand IOC-lookup function (VirusTotal/GreyNoise/Shodan/
 * Pulsedive/Hybrid Analysis/...) with a minimum spacing between live calls to
 * that source. The debounce on the search input helps but doesn't fully
 * prevent bursts (e.g. searching several different indicators back to back
 * can still exceed a 4-req/min free tier), so this enforces it server-side,
 * shared across every viewer of the dashboard.
 */
export function throttleAndCache(source, minIntervalMs, fn) {
  return async (type, value) => {
    const key = `${source}:${type}:${value.trim().toLowerCase()}`;
    const cached = cache.get(key);
    if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) return cached.result;

    const lastCall = lastCallAt.get(source) ?? 0;
    const elapsed = Date.now() - lastCall;
    if (elapsed < minIntervalMs) {
      throw new ApiError(`${source} rate limit reached, try again in ${Math.ceil((minIntervalMs - elapsed) / 1000)}s`, source, 429);
    }
    lastCallAt.set(source, Date.now());

    const result = await fn(type, value);
    cache.set(key, { result, cachedAt: Date.now() });
    return result;
  };
}
