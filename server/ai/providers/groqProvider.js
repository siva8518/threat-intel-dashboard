// Groq Llama 3.3 70B. Deliberately does NOT reuse server/groqClient.js's
// groqJson() -- that helper always forces response_format: json_object for
// its own callers (server/aiThreatSummary.js's structured report, and
// server/combinedExtraction.js's entity extraction), which would corrupt a
// plain-text summarize(prompt) call here. Same endpoint/auth/model as that
// file, just without the forced JSON mode -- server/groqClient.js and its
// existing callers are untouched by this addition.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.groq.com/openai/v1/chat/completions";
const REQUEST_TIMEOUT_MS = 30_000;
const LABEL = "Groq";

export const groqProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.groq.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.groq.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    const { apiKey, model } = AI_ROUTER_CONFIG.groq;
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
    if (!summary) throw classifyProviderError(LABEL, new Error("Groq returned no usable content"));

    return { summary, tokensUsed: data.usage?.total_tokens };
  },
};
