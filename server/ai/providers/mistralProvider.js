// Mistral Small, served through Mistral's own OpenAI-compatible chat
// completions endpoint -- same request/response shape as groqProvider.js,
// just a different base URL/key.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.mistral.ai/v1/chat/completions";
// 60s -- see groqProvider.js's comment on the same constant; this app's
// heaviest LLM call (server/aiThreatSummary.js's structured report) needs
// the headroom.
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Mistral";

/**
 * Shared request path for both summarize() and summarizeJson().
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean}} options
 */
async function callMistral(prompt, { systemPrompt, temperature, jsonMode = false } = {}) {
  const { apiKey, model } = AI_ROUTER_CONFIG.mistral;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("Mistral returned no usable content"));

  return { summary, tokensUsed: data.usage?.total_tokens };
}

export const mistralProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.mistral.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.mistral.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    return callMistral(prompt);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number}} [options]
   * @returns {Promise<{summary: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callMistral(userPrompt, { ...options, jsonMode: true });
  },
};
