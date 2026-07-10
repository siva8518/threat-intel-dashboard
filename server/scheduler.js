import { withRetry } from "./lib/retry.js";
import { log } from "./lib/log.js";
import * as cache from "./cache.js";

/**
 * Runs every connector once immediately on boot, then again on its own
 * intervalMs forever. This is what makes "background sync" real: it runs
 * regardless of whether any browser tab is open, so the cache is always
 * warm and every viewer shares the same upstream call instead of each tab
 * polling independently.
 */
export function startScheduler(connectors) {
  for (const connector of connectors) {
    runSync(connector);
    setInterval(() => runSync(connector), connector.intervalMs);
  }
}

async function runSync(connector) {
  cache.markSyncing(connector.id, true);
  try {
    const data = await withRetry(() => connector.fetch(), {
      retries: 2,
      baseDelayMs: 1000,
      // Don't burn retries on "not configured" (401) or "not found" (404) --
      // those won't resolve by retrying, only a transient/5xx/network error will.
      isRetryable: (error) => !(error.status === 401 || error.status === 404),
    });
    cache.setSuccess(connector.id, data);
    log.info(connector.id, "sync ok");
  } catch (error) {
    cache.setError(connector.id, error);
    log.error(connector.id, `sync failed: ${error.message}`);
  }
}
