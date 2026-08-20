// NVIDIA NIM -- free developer tier at build.nvidia.com, OpenAI-compatible
// endpoint (integrate.api.nvidia.com), same request/response shape every
// other OpenAI-compatible provider here uses (see groqProvider.js). Model
// availability confirmed live: meta/llama-3.3-70b-instruct and
// meta/llama-3.1-70b-instruct both hung indefinitely (30-90s, no response,
// not even an error) on this account -- nvidia/llama-3.3-nemotron-super-49b-v1
// answers normally and supports response_format: json_object, so that's the
// default model instead. meta/llama-3.1-8b-instruct confirmed working for
// the fast tier.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://integrate.api.nvidia.com/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "NVIDIA NIM";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callNvidia(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.nvidia;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("NVIDIA NIM returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const nvidiaProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.nvidia.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.nvidia.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callNvidia(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callNvidia(userPrompt, { ...options, jsonMode: true });
  },
};
