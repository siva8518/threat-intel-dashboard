// Shared error normalization for every AI provider -- lets each provider
// file focus only on its own request/response shape, instead of every one
// of them re-deriving "is this a 429 vs a timeout vs a network blip" from
// scratch. Built on the same ApiError foundation every other client in this
// app already uses (see server/lib/http.js), so this slots into the
// existing error-handling conventions rather than inventing a new one.
import { ApiError } from "../lib/http.js";

/**
 * @typedef {"rate_limited"|"quota_exceeded"|"timeout"|"server_error"|"network_error"|"not_configured"|"other"} AIProviderFailureReason
 */

export class AIProviderUnavailableError extends Error {
  /**
   * @param {string} providerLabel
   * @param {AIProviderFailureReason} reason
   * @param {string} detail
   */
  constructor(providerLabel, reason, detail) {
    super(`${providerLabel} unavailable (${reason}): ${detail}`);
    this.name = "AIProviderUnavailableError";
    this.providerLabel = providerLabel;
    this.reason = reason;
  }
}

const RETRYABLE_SERVER_STATUSES = new Set([500, 502, 503]);
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
    if (error.status === 429 || RATE_LIMIT_PATTERN.test(message)) {
      return new AIProviderUnavailableError(providerLabel, "rate_limited", message);
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
