// In-memory cache: { [sourceId]: { data, updatedAt, error, lastAttempt, isSyncing } }
//
// Deliberately not Redis/SQLite/file-backed -- this is a single-process app,
// and losing the cache on restart (falling back to an immediate resync) is
// an acceptable tradeoff for staying simple. If this ever needs to survive
// restarts or run across multiple instances, swap this module for a Redis
// client without touching scheduler.js or the connectors.
const store = new Map();

export function getEntry(sourceId) {
  return (
    store.get(sourceId) ?? {
      data: undefined,
      updatedAt: null,
      error: null,
      lastAttempt: null,
      isSyncing: false,
    }
  );
}

export function getAllEntries() {
  return Object.fromEntries(store.entries());
}

export function markSyncing(sourceId, isSyncing) {
  store.set(sourceId, { ...getEntry(sourceId), isSyncing });
}

/** Successful sync: replace data, clear the error, stamp updatedAt. */
export function setSuccess(sourceId, data) {
  store.set(sourceId, {
    data,
    updatedAt: Date.now(),
    error: null,
    lastAttempt: Date.now(),
    isSyncing: false,
  });
}

/** Failed sync: keep the last-known-good data (if any) so the UI degrades gracefully. */
export function setError(sourceId, error) {
  const previous = getEntry(sourceId);
  store.set(sourceId, {
    data: previous.data,
    updatedAt: previous.updatedAt,
    error: error.message ?? String(error),
    lastAttempt: Date.now(),
    isSyncing: false,
  });
}
