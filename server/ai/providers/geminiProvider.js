// Gemini 2.5 Flash via Google's REST API -- no SDK, same raw-fetch
// convention every other client in this app uses (see server/lib/http.js).
// Auth goes in a header (x-goog-api-key), not the ?key= query param
// Google's docs also support -- keeps the API key out of URLs/logs/proxies.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models";
// 60s, not a shorter default -- confirmed live that server/aiThreatSummary.js's
// full structured-report call (this app's single heaviest LLM call, an
// 11.5k+ token completion) genuinely needs it; a 30s timeout made this
// provider fail over on every such call even when otherwise healthy.
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Gemini";

/**
 * Shared request path for both summarize() and summarizeJson() -- they only
 * differ in whether generationConfig.responseMimeType is set, so the actual
 * fetch/error-classify/response-parse logic lives here once instead of
 * being duplicated per method.
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean}} options
 */
async function callGemini(prompt, { systemPrompt, temperature, jsonMode = false } = {}) {
  const { apiKey, model } = AI_ROUTER_CONFIG.gemini;
  const body = {
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: {
      ...(temperature !== undefined ? { temperature } : {}),
      ...(jsonMode ? { responseMimeType: "application/json" } : {}),
    },
  };
  if (systemPrompt) body.systemInstruction = { parts: [{ text: systemPrompt }] };

  let data;
  try {
    data = await fetchJson(`${BASE_URL}/${model}:generateContent`, {
      source: LABEL,
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify(body),
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    throw classifyProviderError(LABEL, error);
  }

  // A blocked/empty response has no candidates at all (safety filters,
  // recitation checks, etc.) rather than an HTTP error -- treated as a
  // generic provider failure so the router still fails over cleanly
  // instead of returning an empty summary as if it succeeded.
  const summary = data.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!summary) throw classifyProviderError(LABEL, new Error("Gemini returned no usable content (likely blocked by safety filters or an empty candidate list)"));

  return { summary, tokensUsed: data.usageMetadata?.totalTokenCount };
}

/**
 * Implements the AIProvider shape every server/ai/providers/*.js file
 * shares: { label, model, isConfigured(), summarize(prompt), summarizeJson(prompt, opts) }.
 * aiRouter.js only ever calls these members -- it never needs to know
 * Gemini's request/response shape is different from Groq's or Cohere's.
 */
export const geminiProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.gemini.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.gemini.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    return callGemini(prompt);
  },

  /**
   * Same call, but requests Gemini's native JSON output mode and allows a
   * separate system instruction -- for structured-report callers like
   * server/aiThreatSummary.js that need a schema-following JSON response,
   * not free-text.
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number}} [options]
   * @returns {Promise<{summary: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callGemini(userPrompt, { ...options, jsonMode: true });
  },
};
