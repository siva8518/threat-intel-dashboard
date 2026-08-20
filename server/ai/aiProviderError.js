// Shared error normalization for every AI provider -- lets each provider
// file focus only on its own request/response shape, instead of every one
// of them re-deriving "is this a 429 vs a timeout vs a network blip" from
// scratch. Built on the same ApiError foundation every other client in this
// app already uses (see server/lib/http.js), so this slots into the
// existing error-handling conventions rather than inventing a new one.
import { ApiError } from "../lib/http.js";

/**
 * @typedef {"rate_limited"|"quota_exceeded"|"timeout"|"server_error"|"network_error"|"auth_error"|"not_configured"|"other"} AIProviderFailureReason
 */

export class AIProviderUnavailableError extends Error {
  /**
   * @param {string} providerLabel
   * @param {AIProviderFailureReason} reason
   * @param {string} detail
   * @param {number} [retryAfterMs] - from the upstream response's Retry-After header, when present (see server/lib/http.js#parseRetryAfterMs)
   */
  constructor(providerLabel, reason, detail, retryAfterMs) {
    super(`${providerLabel} unavailable (${reason}): ${detail}`);
    this.name = "AIProviderUnavailableError";
    this.providerLabel = providerLabel;
    this.reason = reason;
    this.retryAfterMs = retryAfterMs;
  }
}

const RETRYABLE_SERVER_STATUSES = new Set([500, 502, 503]);
const AUTH_STATUSES = new Set([401, 403]);
const QUOTA_PATTERN = /quota|resource_exhausted|insufficient_quota/i;
const RATE_LIMIT_PATTERN = /rate.?limit/i;
const TIMEOUT_PATTERN = /timed out/i;

/**
 * Classifies any error thrown while calling a provider's API into the
 * normalized AIProviderUnavailableError shape aiRouter.js logs and
 * failover-decides on. Order matters: quota/rate-limit message sniffing
 * runs before the generic status-code checks, since some providers signal
 * "you're out of quota" via a 400 with a message rather than a dedicated
 * status code.
 * @param {string} providerLabel
 * @param {unknown} error
 * @returns {AIProviderUnavailableError}
 */
export function classifyProviderError(providerLabel, error) {
  const message = error?.message ?? String(error);

  if (QUOTA_PATTERN.test(message)) return new AIProviderUnavailableError(providerLabel, "quota_exceeded", message);

  if (error instanceof ApiError) {
    // 402 -- confirmed live across multiple providers (Hugging Face:
    // "depleted your monthly included credits"; SambaNova:
    // PAYMENT_METHOD_REQUIRED) that this is always billing/credit
    // exhaustion, just worded differently per provider, never matching
    // QUOTA_PATTERN's literal "quota" text above. Checked before the 429
    // branch below since QUOTA_PATTERN already runs first for anything that
    // does say "quota" -- this catches the ones that don't. Matters because
    // "other" gets a 5-10min retry cooldown while quota_exceeded gets a full
    // day; misclassifying this meant retrying a monthly cap every 10
    // minutes for the rest of the month.
    if (error.status === 402) {
      return new AIProviderUnavailableError(providerLabel, "quota_exceeded", message);
    }
    if (error.status === 429 || RATE_LIMIT_PATTERN.test(message)) {
      return new AIProviderUnavailableError(providerLabel, "rate_limited", message, error.retryAfterMs);
    }
    // 401/403 -- a bad/expired key or missing permission. This never
    // self-resolves by waiting, unlike every other reason here, so
    // aiRouter.js's retry policy must never retry it and providerHealth.js
    // must cool it down far longer than a transient failure.
    if (AUTH_STATUSES.has(error.status)) {
      return new AIProviderUnavailableError(providerLabel, "auth_error", message);
    }
    if (error.status === undefined && TIMEOUT_PATTERN.test(message)) {
      return new AIProviderUnavailableError(providerLabel, "timeout", message);
    }
    if (RETRYABLE_SERVER_STATUSES.has(error.status)) {
      return new AIProviderUnavailableError(providerLabel, "server_error", message);
    }
    if (error.status === undefined) {
      return new AIProviderUnavailableError(providerLabel, "network_error", message);
    }
  }

  return new AIProviderUnavailableError(providerLabel, "other", message);
}
