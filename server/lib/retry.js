/**
 * Runs fn() with exponential-backoff retries. Used by every connector so a
 * transient upstream hiccup (timeout, 5xx, network blip) doesn't take a
 * source offline until the next scheduled sync, but a hard failure (401,
 * 404, persistent 429) still surfaces quickly instead of hammering the
 * upstream with a full retry budget.
 */
export async function withRetry(fn, { retries = 3, baseDelayMs = 500, isRetryable } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const retryable = isRetryable ? isRetryable(error) : true;
      if (!retryable || attempt === retries) break;
      const delay = baseDelayMs * 2 ** attempt;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}
