// Ollama Cloud -- free tier of Ollama's hosted inference (not the local
// llama-runner, the cloud API at ollama.com). Own request/response envelope
// (native /api/chat, not the OpenAI chat shape most providers here use):
// {model, messages, stream: false, format: "json"?} in, {message: {content},
// prompt_eval_count, eval_count} out -- confirmed against docs.ollama.com/api/chat.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://ollama.com/api/chat";
const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Ollama Cloud";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callOllama(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.ollama;
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
        stream: false,
        ...(temperature !== undefined ? { options: { temperature } } : {}),
        ...(jsonMode ? { format: "json" } : {}),
      }),
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    throw classifyProviderError(LABEL, error);
  }

  const summary = data?.message?.content;
  if (!summary) throw classifyProviderError(LABEL, new Error("Ollama Cloud returned no usable content"));

  const tokensUsed = (data.prompt_eval_count ?? 0) + (data.eval_count ?? 0) || undefined;
  return { summary, model, tokensUsed };
}

export const ollamaProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.ollama.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.ollama.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callOllama(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callOllama(userPrompt, { ...options, jsonMode: true });
  },
};
