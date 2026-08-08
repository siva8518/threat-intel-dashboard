// Hugging Face's unified Inference Providers router
// (router.huggingface.co) -- OpenAI-compatible chat completions endpoint
// that itself fans out to whichever backing inference provider currently
// serves the requested model, same request/response shape as groqProvider.js.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://router.huggingface.co/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Hugging Face";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callHuggingFace(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.huggingface;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("Hugging Face returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const huggingFaceProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.huggingface.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.huggingface.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callHuggingFace(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callHuggingFace(userPrompt, { ...options, jsonMode: true });
  },
};
