// Groq's implementation of the shared AIProvider shape every server/ai/providers/*.js
// file exposes -- summarize() plain-text, summarizeJson() forcing
// response_format: json_object. Defaults to Llama 3.3 70B; requests Llama
// 3.1 8B Instant instead when called with {tier: "fast"} (see
// server/ai/config.js's groq.fastModel).
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.groq.com/openai/v1/chat/completions";
// 60s -- this app's heaviest LLM call (server/aiThreatSummary.js's
// structured report) needs the headroom.
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Groq";

/**
 * Shared request path for both summarize() and summarizeJson().
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callGroq(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.groq;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("Groq returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const groqProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.groq.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.groq.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callGroq(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callGroq(userPrompt, { ...options, jsonMode: true });
  },
};
