// Cohere Command R via Cohere's v2 chat API.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.cohere.com/v2/chat";
// 60s -- see geminiProvider.js's comment on the same constant; this app's
// heaviest LLM call (server/aiThreatSummary.js's structured report) needs
// the headroom.
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Cohere";

/**
 * Shared request path for both summarize() and summarizeJson().
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callCohere(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.cohere;
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

  // Cohere v2's chat response nests text inside a content-block array
  // (the same "array of typed content parts" shape Anthropic/OpenAI's
  // newer APIs use) -- find the first text block rather than assuming
  // index 0 is always text, in case a response ever includes other block
  // types (tool calls, thinking blocks, etc.) first.
  const textBlock = data.message?.content?.find((block) => block.type === "text");
  const summary = textBlock?.text;
  if (!summary) throw classifyProviderError(LABEL, new Error("Cohere returned no usable text content"));

  return { summary, model, tokensUsed: data.usage?.tokens?.output_tokens };
}

export const cohereProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.cohere.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.cohere.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callCohere(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callCohere(userPrompt, { ...options, jsonMode: true });
  },
};
