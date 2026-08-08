/**
 * Runs fn() with exponential-backoff retries. Used by every connector so a
 * transient upstream hiccup (timeout, 5xx, network blip) doesn't take a
 * source offline until the next scheduled sync, but a hard failure (401,
 * 404, persistent 429) still surfaces quickly instead of hammering the
 * upstream with a full retry budget.
 *
 * Delay includes +/-25% jitter around the exponential base so concurrent
 * callers retrying the same upstream (e.g. several investigation panels
 * firing at once) don't all retry in lockstep -- purely additive, no
 * existing caller asserts exact timing.
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
      const base = baseDelayMs * 2 ** attempt;
      const jitter = base * 0.25 * (Math.random() * 2 - 1);
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, base + jitter)));
    }
  }
  throw lastError;
}
