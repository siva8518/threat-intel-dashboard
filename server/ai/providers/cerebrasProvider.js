// Cerebras Inference via its OpenAI-compatible chat completions endpoint --
// same request/response shape as groqProvider.js, just a different base
// URL/key/model family. Cerebras's own hardware is optimized for very low
// latency, which is why it sits right after Gemini in the default fallback
// chain (see aiRouter.js's PROVIDERS order).
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.cerebras.ai/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Cerebras";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callCerebras(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.cerebras;
  const model = tier === "fast" ? fastModel : defaultModel;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("Cerebras returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const cerebrasProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.cerebras.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.cerebras.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callCerebras(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callCerebras(userPrompt, { ...options, jsonMode: true });
  },
};
