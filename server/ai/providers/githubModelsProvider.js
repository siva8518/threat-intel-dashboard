// GitHub Models via its OpenAI-compatible chat completions endpoint --
// same request/response shape as groqProvider.js, authenticated with a
// GitHub personal access token (fine-grained, "Models" read permission)
// rather than a dedicated API key.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://models.github.ai/inference/chat/completions";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "GitHub Models";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callGithubModels(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.githubModels;
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
  if (!summary) throw classifyProviderError(LABEL, new Error("GitHub Models returned no usable content"));

  return { summary, model, tokensUsed: data.usage?.total_tokens };
}

export const githubModelsProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.githubModels.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.githubModels.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callGithubModels(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callGithubModels(userPrompt, { ...options, jsonMode: true });
  },
};
