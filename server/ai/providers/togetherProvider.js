// Together AI via its OpenAI-compatible chat completions endpoint -- same
// request/response shape as groqProvider.js. Together's free tier is
// trial-credit-based rather than permanently free like most other
// providers here (see config.js's comment on the default model), which is
// why it sits later in the default fallback chain.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.together.xyz/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Together AI";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callTogether(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.together;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("Together AI returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const togetherProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.together.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.together.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callTogether(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callTogether(userPrompt, { ...options, jsonMode: true });
  },
};
