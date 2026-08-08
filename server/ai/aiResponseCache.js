// In-memory TTL cache for AI responses, opt-in via {cacheKey} on
// aiRouter.summarize()/summarizeJson() -- avoids re-spending AI credits
// generating the literal same analysis twice (e.g. re-opening the same
// entity's Investigation Workspace within the TTL window re-runs identical
// prompts over identical evidence). Deliberately in-memory only: entries
// are cheap to regenerate (that's the whole fallback path this app already
// has), so there's no need for cross-restart persistence the way the
// request log (aiRequestLog.js) genuinely needs it for usage history.
//
// Callers build `cacheKey` themselves from whatever actually determines
// their output (task + a stable hash of the evidence/context object they're
// about to send) -- this module only stores/expires by that key, it has no
// opinion on what should be cacheable.
const DEFAULT_TTL_MS = 30 * 60_000; // 30 minutes -- long enough to absorb a user re-opening the same investigation, short enough that newly-ingested intelligence isn't shown stale for long

const store = new Map();

export function getCached(cacheKey) {
  const entry = store.get(cacheKey);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    store.delete(cacheKey);
    return null;
  }
  return entry.value;
}

export function setCached(cacheKey, value, ttlMs = DEFAULT_TTL_MS) {
  store.set(cacheKey, { value, expiresAt: Date.now() + ttlMs });
}

/** Simple, dependency-free stable hash for building cacheKeys from arbitrary JSON-serializable context objects (djb2 over a deterministic-order JSON string). Not cryptographic -- collision risk is irrelevant here, a false cache hit only ever costs a re-render of a slightly stale AI narrative behind an evidence object that would have hashed identically anyway. */
export function hashForCacheKey(value) {
  const json = JSON.stringify(value, Object.keys(value ?? {}).sort());
  let hash = 5381;
  for (let i = 0; i < json.length; i++) {
    hash = (hash * 33) ^ json.charCodeAt(i);
  }
  return (hash >>> 0).toString(36);
}
