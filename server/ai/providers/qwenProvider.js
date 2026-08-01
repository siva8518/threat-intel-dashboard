// Qwen 3 32B, served through OpenRouter's unified OpenAI-compatible API --
// one API surface/key covers every model OpenRouter hosts, so this is the
// only place "which OpenRouter model" is decided (server/ai/config.js).
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://openrouter.ai/api/v1/chat/completions";
// 60s -- see geminiProvider.js's comment on the same constant; this app's
// heaviest LLM call (server/aiThreatSummary.js's structured report) needs
// the headroom.
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "OpenRouter - Qwen";

/**
 * Shared request path for both summarize() and summarizeJson() -- they only
 * differ in an optional system message and response_format, so the actual
 * fetch/error-classify/response-parse logic lives here once.
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean}} options
 */
async function callQwen(prompt, { systemPrompt, temperature, jsonMode = false } = {}) {
  const { apiKey, model } = AI_ROUTER_CONFIG.qwen;
  const messages = systemPrompt ? [{ role: "system", content: systemPrompt }, { role: "user", content: prompt }] : [{ role: "user", content: prompt }];

  let data;
  try {
    data = await fetchJson(BASE_URL, {
      source: LABEL,
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model,
        messages,
        ...(temperature !== undefined ? { temperature } : {}),
        ...(jsonMode ? { response_format: { type: "json_object" } } : {}),
      }),
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    throw classifyProviderError(LABEL, error);
  }

  const summary = data.choices?.[0]?.message?.content;
  if (!summary) throw classifyProviderError(LABEL, new Error("OpenRouter/Qwen returned no usable content"));

  return { summary, tokensUsed: data.usage?.total_tokens };
}

export const qwenProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.qwen.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.qwen.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    return callQwen(prompt);
  },

  /**
   * Same call, but requests OpenAI-compatible JSON-object mode and allows a
   * separate system prompt -- for structured-report callers like
   * server/aiThreatSummary.js.
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number}} [options]
   * @returns {Promise<{summary: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callQwen(userPrompt, { ...options, jsonMode: true });
  },
};
