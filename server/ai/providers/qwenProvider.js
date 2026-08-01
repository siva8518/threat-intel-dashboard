// Qwen 3 32B, served through OpenRouter's unified OpenAI-compatible API --
// one API surface/key covers every model OpenRouter hosts, so this is the
// only place "which OpenRouter model" is decided (server/ai/config.js).
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://openrouter.ai/api/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 30_000;
const LABEL = "OpenRouter - Qwen";

export const qwenProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.qwen.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.qwen.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    const { apiKey, model } = AI_ROUTER_CONFIG.qwen;
    let data;
    try {
      data = await fetchJson(BASE_URL, {
        source: LABEL,
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model, messages: [{ role: "user", content: prompt }] }),
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch (error) {
      throw classifyProviderError(LABEL, error);
    }

    const summary = data.choices?.[0]?.message?.content;
    if (!summary) throw classifyProviderError(LABEL, new Error("OpenRouter/Qwen returned no usable content"));

    return { summary, tokensUsed: data.usage?.total_tokens };
  },
};
