// Groq Llama 3.3 70B. Deliberately does NOT reuse server/groqClient.js's
// groqJson() -- that helper always forces response_format: json_object for
// its own callers (server/combinedExtraction.js's entity extraction), which
// would corrupt a plain-text summarize(prompt) call here. This provider's
// own summarizeJson() below covers the JSON-mode case instead, so
// server/aiThreatSummary.js can go through the router uniformly rather than
// calling groqClient.js directly for one provider and this file for the
// other three. Same endpoint/auth/model as groqClient.js, just implemented
// once more here behind the shared AIProvider shape -- server/groqClient.js
// and server/combinedExtraction.js are untouched by this addition.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.groq.com/openai/v1/chat/completions";
// 60s -- matches server/groqClient.js's own timeout for the same reason:
// this app's heaviest LLM call (server/aiThreatSummary.js's structured
// report) needs the headroom.
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Groq";

/**
 * Shared request path for both summarize() and summarizeJson().
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean}} options
 */
async function callGroq(prompt, { systemPrompt, temperature, jsonMode = false } = {}) {
  const { apiKey, model } = AI_ROUTER_CONFIG.groq;
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

  return { summary, tokensUsed: data.usage?.total_tokens };
}

export const groqProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.groq.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.groq.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    return callGroq(prompt);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number}} [options]
   * @returns {Promise<{summary: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callGroq(userPrompt, { ...options, jsonMode: true });
  },
};
