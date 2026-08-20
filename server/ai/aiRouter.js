// Provider-agnostic AI summarization router. The rest of the app should
// only ever import { aiRouter } from here and call aiRouter.summarize(prompt)
// (plain text) or aiRouter.summarizeJson(prompt, opts) (structured JSON,
// used by server/aiThreatSummary.js's report generation) -- both walk
// PROVIDERS in priority order, retrying each once for a transient failure
// (exponential backoff + jitter, see server/lib/retry.js; NOT retried for
// auth/quota failures, see isRetryableReason below) before failing over to
// the next healthy, non-cooling-down provider, and return a normalized
// result no matter which provider actually answered.
//
// Options accepted alongside {tier}: {task} (one of aiTasks.js's AI_TASK
// labels -- used for telemetry and, absent an explicit {tier}, to pick a
// sensible default) and {cacheKey, cacheTtlMs} (opt-in response caching,
// see aiResponseCache.js) and {minContextWindow} (skip providers whose
// configured context window can't fit this call -- see config.js's
// per-provider contextWindow). Every one of these is optional and additive;
// omitting all of them behaves exactly as this router did before any of
// this existed.
//
// Provider order defaults to Gemini -> Groq -> NVIDIA NIM -> OpenRouter ->
// Ollama Cloud -> Hugging Face -> Cohere -> Together AI -> Cloudflare
// Workers AI -> GitHub Models, overridable via the AI_PROVIDER_ORDER env var
// (comma-separated provider keys, see DEFAULT_ORDER below for the exact
// keys) -- this specific order (Gemini -> Groq -> NVIDIA -> OpenRouter ->
// Ollama -> everything else) was requested directly rather than picked by
// the usual "most generous free tier first" heuristic below. Anthropic,
// Mistral, Cerebras, and SambaNova are deliberately not in this chain --
// all four are paid/billing-gated (confirmed live: SambaNova returns 402
// PAYMENT_METHOD_REQUIRED, balance 0, on every model) and this deployment
// isn't funding them. A removed provider can't show up as a confusing
// "needs billing" entry in the AI Provider Health panel the way an unset
// key would.
//
// Adding an 11th provider is a two-file change: write one more
// server/ai/providers/*.js implementing { label, model, isConfigured(),
// summarize(prompt, opts), summarizeJson(prompt, opts) }, add its config to
// server/ai/config.js, then add one entry to PROVIDER_DEFS below. Nothing
// else here, or in any caller, needs to change.
import { log } from "../lib/log.js";
import { withRetry } from "../lib/retry.js";
import { classifyProviderError } from "./aiProviderError.js";
import { AI_ROUTER_CONFIG } from "./config.js";
import { AI_TASK_DEFAULTS } from "./aiTasks.js";
import * as providerHealth from "./providerHealth.js";
import { recordAiRequest } from "./aiRequestLog.js";
import { getCached, setCached } from "./aiResponseCache.js";
import { geminiProvider } from "./providers/geminiProvider.js";
import { groqProvider } from "./providers/groqProvider.js";
import { nvidiaProvider } from "./providers/nvidiaProvider.js";
import { openRouterProvider } from "./providers/openRouterProvider.js";
import { ollamaProvider } from "./providers/ollamaProvider.js";
import { huggingFaceProvider } from "./providers/huggingFaceProvider.js";
import { cohereProvider } from "./providers/cohereProvider.js";
import { togetherProvider } from "./providers/togetherProvider.js";
import { cloudflareProvider } from "./providers/cloudflareProvider.js";
import { githubModelsProvider } from "./providers/githubModelsProvider.js";

// Default priority order -- see the header comment above for why this
// specific sequence (not the usual "most generous free tier first").
const PROVIDER_DEFS = [
  { key: "gemini", provider: geminiProvider, contextWindow: AI_ROUTER_CONFIG.gemini.contextWindow },
  { key: "groq", provider: groqProvider, contextWindow: AI_ROUTER_CONFIG.groq.contextWindow },
  { key: "nvidia", provider: nvidiaProvider, contextWindow: AI_ROUTER_CONFIG.nvidia.contextWindow },
  { key: "openrouter", provider: openRouterProvider, contextWindow: AI_ROUTER_CONFIG.openrouter.contextWindow },
  { key: "ollama", provider: ollamaProvider, contextWindow: AI_ROUTER_CONFIG.ollama.contextWindow },
  { key: "huggingface", provider: huggingFaceProvider, contextWindow: AI_ROUTER_CONFIG.huggingface.contextWindow },
  { key: "cohere", provider: cohereProvider, contextWindow: AI_ROUTER_CONFIG.cohere.contextWindow },
  { key: "together", provider: togetherProvider, contextWindow: AI_ROUTER_CONFIG.together.contextWindow },
  { key: "cloudflare", provider: cloudflareProvider, contextWindow: AI_ROUTER_CONFIG.cloudflare.contextWindow },
  { key: "githubmodels", provider: githubModelsProvider, contextWindow: AI_ROUTER_CONFIG.githubModels.contextWindow },
];
const DEFAULT_ORDER = PROVIDER_DEFS.map((d) => d.key);

/** Resolves AI_PROVIDER_ORDER (comma-separated provider keys) into an ordered PROVIDER_DEFS list -- unknown keys are dropped with a warning, and any known provider the env var omits is appended at the end rather than silently lost (an incomplete override should still fail over to every configured provider). */
function resolveProviderOrder() {
  const raw = process.env.AI_PROVIDER_ORDER;
  if (!raw) return DEFAULT_ORDER;

  const requested = raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const known = new Set(DEFAULT_ORDER);
  const valid = requested.filter((k) => known.has(k));
  const invalid = requested.filter((k) => !known.has(k));
  if (invalid.length > 0) log.warn("ai-router", `AI_PROVIDER_ORDER contains unknown provider key(s), ignoring: ${invalid.join(", ")} (known keys: ${DEFAULT_ORDER.join(", ")})`);
  if (valid.length === 0) return DEFAULT_ORDER;

  const missing = DEFAULT_ORDER.filter((k) => !valid.includes(k));
  return [...valid, ...missing];
}

const PROVIDERS = resolveProviderOrder().map((key) => PROVIDER_DEFS.find((d) => d.key === key));

// 0 -- fail over to the NEXT provider immediately on a retryable error
// rather than retrying the same one. A same-provider retry only ever adds
// latency (up to REQUEST_TIMEOUT_MS again) betting on the same provider
// recovering; failing over spends that time on a provider that might
// already be healthy instead. Matters a lot for any caller sitting behind a
// hard platform request timeout (e.g. DigitalOcean App Platform's own edge
// timeout, well under a minute) -- one retried timeout used to be enough by
// itself to blow that budget before failover even started.
const RETRIES_PER_PROVIDER = 0;
const RETRY_BASE_DELAY_MS = 1000;

// Only genuinely transient reasons get a same-provider retry. A rate limit
// is handled by the cooldown/circuit-breaker (providerHealth.js) instead of
// a fast retry -- retrying a 429 immediately just spends the retry budget
// hitting the same wall. quota_exceeded/auth_error/other don't self-resolve
// in a second or two, so retrying them wastes latency the failover to the
// next provider could have spent instead.
const RETRYABLE_REASONS = new Set(["timeout", "server_error", "network_error"]);
function isRetryableReason(error) {
  return RETRYABLE_REASONS.has(error?.reason);
}

const REASON_LABEL = {
  rate_limited: "Rate Limited",
  quota_exceeded: "Quota Exceeded",
  timeout: "Timeout",
  server_error: "Server Error",
  network_error: "Network Error",
  auth_error: "Authentication Error",
  not_configured: "Not Configured",
  cooling_down: "Cooling Down",
  other: "Error",
};

// Deliberately plain text, not JSON mode -- a couple of providers here
// (see groqProvider.js) reject response_format: json_object unless the
// prompt itself contains the word "json", which a minimal health-check
// ping has no reason to. Not sent through recordAiRequest/aiRequestLog --
// this is an internal circuit-breaker probe, not real app usage, and
// mixing it into the AI Usage tab's token/request totals would misrepresent
// what this app actually asked providers to do. It IS fully text-logged
// (provider, status, latency) via log.info/warn below, same as every real
// attempt, and it still updates providerHealth exactly like a real
// success/failure would.
async function performHealthCheck(provider) {
  const start = Date.now();
  try {
    await provider.summarize("Respond with the single word: ready", { tier: "fast", temperature: 0 });
    const latency = Date.now() - start;
    providerHealth.recordSuccess(provider.label, latency);
    log.info("ai-router", `Provider: ${provider.label} | Health check: Passed | Latency: ${(latency / 1000).toFixed(1)}s -- returning to production traffic`);
    return true;
  } catch (rawError) {
    const error = rawError.name === "AIProviderUnavailableError" ? rawError : classifyProviderError(provider.label, rawError);
    const latency = Date.now() - start;
    providerHealth.recordFailure(provider.label, error.reason, { retryAfterMs: error.retryAfterMs });
    log.warn("ai-router", `Provider: ${provider.label} | Health check: Failed | Status: ${REASON_LABEL[error.reason] ?? "Error"} | Latency: ${(latency / 1000).toFixed(1)}s -- staying in cooldown`);
    return false;
  }
}

/** Thrown only once every configured, non-cooling-down provider has actually been attempted. */
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
 * @property {number} latency - ms taken by the winning provider's successful attempt (0 for a cache hit)
 * @property {boolean} success - always true when this resolves (throws AllProvidersFailedError otherwise)
 */

/**
 * Shared failover loop for both summarize() and summarizeJson() -- they
 * only differ in which provider method gets called (`summarize` vs.
 * `summarizeJson`) and what arguments it's given; the priority-order walk,
 * cooldown/retry-then-failover behavior, caching, logging/telemetry, and
 * terminal-failure handling are identical, so that logic lives here once
 * instead of twice.
 * @param {"summarize"|"summarizeJson"} method
 * @param {string} promptArg - the prompt/userPrompt positional argument
 * @param {{task?: string, tier?: "fast", cacheKey?: string, cacheTtlMs?: number, minContextWindow?: number, systemPrompt?: string, temperature?: number}} options
 * @returns {Promise<AISummaryResult>}
 */
async function runWithFailover(method, promptArg, options = {}) {
  const { task, cacheKey, cacheTtlMs, minContextWindow } = options;
  const taskDefaults = task ? AI_TASK_DEFAULTS[task] : undefined;

  if (cacheKey) {
    const cached = getCached(cacheKey);
    if (cached) {
      log.info("ai-router", `Task: ${task ?? "unlabeled"} | Cache hit -- skipping provider call entirely`);
      recordAiRequest({ task, provider: cached.provider, model: cached.model, status: "success", latencyMs: 0, cacheHit: true });
      return { ...cached, latency: 0 };
    }
  }

  const effectiveMinContextWindow = minContextWindow ?? taskDefaults?.minContextWindow;
  let candidates = PROVIDERS;
  if (effectiveMinContextWindow) {
    const fits = PROVIDERS.filter((d) => (d.contextWindow ?? Infinity) >= effectiveMinContextWindow);
    if (fits.length > 0) candidates = fits;
    else log.warn("ai-router", `No configured provider's context window meets the ${effectiveMinContextWindow}-token hint for this call -- trying the full chain anyway.`);
  }

  // Caller's own {tier} always wins; a task-category default only fills in
  // when the caller didn't ask for one (see aiTasks.js's header comment).
  const callOptions = { ...options, tier: options.tier ?? taskDefaults?.tier };

  const attempts = [];
  const cycleStart = Date.now();

  for (const { provider } of candidates) {
    if (!provider.isConfigured()) {
      log.info("ai-router", `Provider: ${provider.label} | Status: ${REASON_LABEL.not_configured} | Skipping...`);
      attempts.push({ provider: provider.label, reason: "not_configured" });
      continue;
    }

    if (providerHealth.isInCooldown(provider.label)) {
      const seconds = Math.ceil(providerHealth.cooldownRemainingMs(provider.label) / 1000);
      log.info("ai-router", `Provider: ${provider.label} | Status: ${REASON_LABEL.cooling_down} | Retry in ${seconds}s | Skipping...`);
      attempts.push({ provider: provider.label, reason: "cooling_down" });
      continue;
    }

    // Cooldown window just elapsed but nothing has re-verified this
    // provider yet -- run one cheap health check before letting the real
    // request (potentially carrying a large prompt, on a hard platform
    // timeout budget) be the thing that discovers it's still down.
    if (providerHealth.isPendingHealthCheck(provider.label)) {
      const healthy = await performHealthCheck(provider);
      if (!healthy) {
        attempts.push({ provider: provider.label, reason: providerHealth.getLastFailureReason(provider.label) ?? "other" });
        continue;
      }
    }

    const start = Date.now();
    try {
      const result = await withRetry(() => provider[method](promptArg, callOptions), {
        retries: RETRIES_PER_PROVIDER,
        baseDelayMs: RETRY_BASE_DELAY_MS,
        isRetryable: isRetryableReason,
      });
      const latency = Date.now() - start;
      // result.model is the actual model that answered -- differs from
      // provider.model (the provider's default) whenever the caller passed
      // {tier: "fast"}, so a fast-tier response never gets misreported as
      // having come from the default model.
      const model = result.model ?? provider.model;
      const tokenPart = result.tokensUsed ? ` | Tokens: ${result.tokensUsed}` : "";
      const priorFailures = attempts.filter((a) => a.reason !== "not_configured" && a.reason !== "cooling_down");
      const fallbackPart = priorFailures.length > 0 ? ` | Fallback from: ${priorFailures.map((a) => a.provider).join(", ")}` : "";
      log.info("ai-router", `Provider: ${provider.label} | Model: ${model} | Status: Success | Latency: ${(latency / 1000).toFixed(1)}s${tokenPart}${fallbackPart}`);

      providerHealth.recordSuccess(provider.label, latency);
      recordAiRequest({ task, provider: provider.label, model, status: "success", latencyMs: latency, totalTokens: result.tokensUsed, fallbackUsed: attempts.length > 0 });

      const finalResult = { provider: provider.label, model, summary: result.summary, latency, success: true };
      if (cacheKey) setCached(cacheKey, finalResult, cacheTtlMs);
      return finalResult;
    } catch (rawError) {
      // Providers already classify their own errors before throwing (see
      // aiProviderError.js) -- this fallback only matters if one somehow
      // throws something unclassified.
      const error = rawError.name === "AIProviderUnavailableError" ? rawError : classifyProviderError(provider.label, rawError);
      const latency = Date.now() - start;
      attempts.push({ provider: provider.label, reason: error.reason, message: error.message });
      log.warn("ai-router", `Provider: ${provider.label} | Model: ${provider.model} | Status: ${REASON_LABEL[error.reason] ?? "Error"} | Latency: ${(latency / 1000).toFixed(1)}s | Failing over...`);

      providerHealth.recordFailure(provider.label, error.reason, { retryAfterMs: error.retryAfterMs });
      recordAiRequest({ task, provider: provider.label, model: provider.model, status: "failure", latencyMs: latency, errorReason: error.reason });
    }
  }

  const totalLatency = Date.now() - cycleStart;
  const failoverCount = attempts.filter((a) => a.reason !== "not_configured" && a.reason !== "cooling_down").length;
  log.error("ai-router", `All providers exhausted after ${failoverCount} failover(s), ${(totalLatency / 1000).toFixed(1)}s total -- summarization unavailable`);
  throw new AllProvidersFailedError(attempts);
}

/**
 * Sends `prompt` to the first configured, healthy (not cooling down),
 * working provider in priority order. A provider not configured (no API
 * key) or currently cooling down from a recent failure is skipped without
 * counting as a failure. A provider that errors with a transient reason is
 * retried once, then skipped as a failover; auth/quota failures fail over
 * immediately. Only throws once every configured, non-cooling-down provider
 * has failed.
 * @param {string} prompt
 * @param {{task?: string, tier?: "fast", cacheKey?: string, cacheTtlMs?: number, minContextWindow?: number}} [options]
 * @returns {Promise<AISummaryResult>}
 */
export async function summarize(prompt, options = {}) {
  return runWithFailover("summarize", prompt, options);
}

/**
 * Same failover behavior as summarize(), but requests each provider's
 * native structured/JSON-object response mode and allows a separate system
 * prompt -- for structured-report callers like server/aiThreatSummary.js
 * that need a schema-following JSON response, not free text. `result.summary`
 * is the raw JSON text (still a string); parsing/validating it against the
 * caller's own schema is the caller's job.
 * @param {string} userPrompt
 * @param {{systemPrompt?: string, temperature?: number, task?: string, tier?: "fast", cacheKey?: string, cacheTtlMs?: number, minContextWindow?: number}} [options]
 * @returns {Promise<AISummaryResult>}
 */
export async function summarizeJson(userPrompt, options = {}) {
  return runWithFailover("summarizeJson", userPrompt, options);
}

/** Per-provider health/status snapshot for the admin AI Provider Health panel -- see server/routes/dashboard.js's /ai-provider-health route. */
export function getProviderHealthSnapshot() {
  return providerHealth.getHealthSnapshot(PROVIDERS.map(({ provider }) => ({ label: provider.label, model: provider.model, configured: provider.isConfigured() })));
}

export const aiRouter = { summarize, summarizeJson };
