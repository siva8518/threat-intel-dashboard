// OpenRouter via its OpenAI-compatible chat completions endpoint --
// deliberately treated as a MODEL ROUTER rather than one fixed model: which
// upstream model actually answers is picked by AI_ROUTER_CONFIG.openrouter's
// model string (OPENROUTER_MODEL env override), which can point at any
// model in OpenRouter's catalog, not just the free-tagged default this app
// ships with.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://openrouter.ai/api/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "OpenRouter";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callOpenRouter(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.openrouter;
  const model = tier === "fast" ? fastModel : defaultModel;
  const messages = systemPrompt ? [{ role: "system", content: systemPrompt }, { role: "user", content: prompt }] : [{ role: "user", content: prompt }];

  let data;
  try {
    data = await fetchJson(BASE_URL, {
      source: LABEL,
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        // OpenRouter asks callers to identify themselves for its own
        // per-app rate-limit/analytics dashboard -- optional, but a good
        // citizen default rather than an anonymous request.
        "HTTP-Referer": "https://github.com/threat-intel-dashboard",
        "X-Title": "Threat Intelligence Dashboard",
      },
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
  if (!summary) throw classifyProviderError(LABEL, new Error("OpenRouter returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const openRouterProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.openrouter.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.openrouter.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callOpenRouter(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callOpenRouter(userPrompt, { ...options, jsonMode: true });
  },
};
