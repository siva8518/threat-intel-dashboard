// Provider-agnostic AI summarization router. The rest of the app should
// only ever import { aiRouter } from here and call aiRouter.summarize(prompt)
// (plain text) or aiRouter.summarizeJson(prompt, opts) (structured JSON,
// used by server/aiThreatSummary.js's report generation) -- both walk
// PROVIDERS in priority order, retrying each once (exponential backoff, see
// server/lib/retry.js) before failing over to the next, and return a
// normalized result no matter which provider actually answered.
//
// Both methods also accept an optional {tier: "fast"} to request each
// provider's smaller/cheaper model (see server/ai/config.js's per-provider
// fastModel) instead of its default -- for high-volume callers like
// server/combinedExtraction.js that need throughput more than the default
// model's extra quality. Omitting `tier` behaves exactly as before this
// existed.
//
// Adding a 6th provider is a two-file change: write one more
// server/ai/providers/*.js implementing { label, model, isConfigured(),
// summarize(prompt, opts), summarizeJson(prompt, opts) }, then add it to the
// PROVIDERS array below. Nothing else here, or in any caller, needs to
// change.
import { log } from "../lib/log.js";
import { withRetry } from "../lib/retry.js";
import { classifyProviderError } from "./aiProviderError.js";
import { geminiProvider } from "./providers/geminiProvider.js";
import { mistralProvider } from "./providers/mistralProvider.js";
import { groqProvider } from "./providers/groqProvider.js";
import { cohereProvider } from "./providers/cohereProvider.js";

// Priority order: Gemini 2.5 Flash -> Mistral Small -> Groq Llama 3.3 70B ->
// Cohere Command R.
const PROVIDERS = [geminiProvider, mistralProvider, groqProvider, cohereProvider];

const RETRIES_PER_PROVIDER = 1; // "retry each provider once" -- 2 total attempts per provider before failing over
const RETRY_BASE_DELAY_MS = 1000;

const REASON_LABEL = {
  rate_limited: "Rate Limited",
  quota_exceeded: "Quota Exceeded",
  timeout: "Timeout",
  server_error: "Server Error",
  network_error: "Network Error",
  not_configured: "Not Configured",
  other: "Error",
};

/** Thrown only once every configured provider has actually been attempted. */
export class AllProvidersFailedError extends Error {
  /** @param {{provider: string, reason: string, message?: string}[]} attempts */
  constructor(attempts) {
    const detail = attempts.map((a) => `${a.provider} (${REASON_LABEL[a.reason] ?? a.reason})`).join(", ");
    super(`All AI providers failed or were unavailable: ${detail}`);
    this.name = "AllProvidersFailedError";
    this.attempts = attempts;
  }
}

/**
 * @typedef {Object} AISummaryResult
 * @property {string} provider - which provider answered, e.g. "Groq"
 * @property {string} model - the specific model used, e.g. "llama-3.3-70b-versatile"
 * @property {string} summary - the generated text
 * @property {number} latency - ms taken by the winning provider's successful attempt
 * @property {boolean} success - always true when this resolves (throws AllProvidersFailedError otherwise)
 */

/**
 * Shared failover loop for both summarize() and summarizeJson() -- they
 * only differ in which provider method gets called (`summarize` vs.
 * `summarizeJson`) and what arguments it's given; the priority-order walk,
 * retry-then-failover behavior, logging, and terminal-failure handling are
 * identical, so that logic lives here once instead of twice.
 * @param {"summarize"|"summarizeJson"} method
 * @param {unknown[]} callArgs - forwarded to provider[method](...callArgs)
 * @returns {Promise<AISummaryResult>}
 */
async function runWithFailover(method, callArgs) {
  const attempts = [];
  const cycleStart = Date.now();

  for (const provider of PROVIDERS) {
    if (!provider.isConfigured()) {
      log.info("ai-router", `Provider: ${provider.label} | Status: ${REASON_LABEL.not_configured} | Skipping...`);
      attempts.push({ provider: provider.label, reason: "not_configured" });
      continue;
    }

    const start = Date.now();
    try {
      const result = await withRetry(() => provider[method](...callArgs), {
        retries: RETRIES_PER_PROVIDER,
        baseDelayMs: RETRY_BASE_DELAY_MS,
      });
      const latency = Date.now() - start;
      const tokenPart = result.tokensUsed ? ` | Tokens: ${result.tokensUsed}` : "";
      const failoverPart = attempts.length > 0 ? ` | Failovers: ${attempts.length}` : "";
      log.info("ai-router", `Provider: ${provider.label} | Status: Success | Latency: ${(latency / 1000).toFixed(1)}s${tokenPart}${failoverPart}`);

      // result.model is the actual model that answered -- differs from
      // provider.model (the provider's default) whenever the caller passed
      // {tier: "fast"}, so a fast-tier response never gets misreported as
      // having come from the default model.
      return { provider: provider.label, model: result.model ?? provider.model, summary: result.summary, latency, success: true };
    } catch (rawError) {
      // Providers already classify their own errors before throwing (see
      // aiProviderError.js) -- this fallback only matters if one somehow
      // throws something unclassified.
      const error = rawError.name === "AIProviderUnavailableError" ? rawError : classifyProviderError(provider.label, rawError);
      const latency = Date.now() - start;
      attempts.push({ provider: provider.label, reason: error.reason, message: error.message });
      log.warn("ai-router", `Provider: ${provider.label} | Status: ${REASON_LABEL[error.reason] ?? "Error"} | Latency: ${(latency / 1000).toFixed(1)}s | Failing over...`);
    }
  }

  const totalLatency = Date.now() - cycleStart;
  const failoverCount = attempts.filter((a) => a.reason !== "not_configured").length;
  log.error("ai-router", `All providers exhausted after ${failoverCount} failover(s), ${(totalLatency / 1000).toFixed(1)}s total -- summarization unavailable`);
  throw new AllProvidersFailedError(attempts);
}

/**
 * Sends `prompt` to the first configured, working provider in priority
 * order. A provider not configured (no API key) is skipped without
 * counting as a failure. A provider that errors is retried once, then
 * skipped as a failover. Only throws once every configured provider has
 * failed.
 * @param {string} prompt
 * @param {{tier?: "fast"}} [options] - pass {tier: "fast"} to request each
 *   provider's smaller/cheaper model instead of its default (see
 *   AI_ROUTER_CONFIG's per-provider fastModel) -- for high-volume callers
 *   like server/combinedExtraction.js where throughput matters more than
 *   the default model's extra quality.
 * @returns {Promise<AISummaryResult>}
 */
export async function summarize(prompt, options = {}) {
  return runWithFailover("summarize", [prompt, options]);
}

/**
 * Same failover behavior as summarize(), but requests each provider's
 * native structured/JSON-object response mode and allows a separate system
 * prompt -- for structured-report callers like server/aiThreatSummary.js
 * that need a schema-following JSON response, not free text. `result.summary`
 * is the raw JSON text (still a string); parsing/validating it against the
 * caller's own schema is the caller's job.
 * @param {string} userPrompt
 * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options] - see summarize()'s `tier` doc above.
 * @returns {Promise<AISummaryResult>}
 */
export async function summarizeJson(userPrompt, options = {}) {
  return runWithFailover("summarizeJson", [userPrompt, options]);
}

export const aiRouter = { summarize, summarizeJson };
