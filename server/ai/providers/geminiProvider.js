// Gemini 2.5 Flash via Google's REST API -- no SDK, same raw-fetch
// convention every other client in this app uses (see server/lib/http.js).
// Auth goes in a header (x-goog-api-key), not the ?key= query param
// Google's docs also support -- keeps the API key out of URLs/logs/proxies.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models";
const REQUEST_TIMEOUT_MS = 30_000;
const LABEL = "Gemini";

/**
 * Implements the AIProvider shape every server/ai/providers/*.js file
 * shares: { label, model, isConfigured(), summarize(prompt) }. aiRouter.js
 * only ever calls these four members -- it never needs to know Gemini's
 * request/response shape is different from Groq's or Cohere's.
 */
export const geminiProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.gemini.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.gemini.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    const { apiKey, model } = AI_ROUTER_CONFIG.gemini;
    let data;
    try {
      data = await fetchJson(`${BASE_URL}/${model}:generateContent`, {
        source: LABEL,
        method: "POST",
        headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
        timeoutMs: REQUEST_TIMEOUT_MS,
      });
    } catch (error) {
      throw classifyProviderError(LABEL, error);
    }

    // A blocked/empty response has no candidates at all (safety filters,
    // recitation checks, etc.) rather than an HTTP error -- treated as a
    // generic provider failure so the router still fails over cleanly
    // instead of returning an empty summary as if it succeeded.
    const summary = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!summary) throw classifyProviderError(LABEL, new Error("Gemini returned no usable content (likely blocked by safety filters or an empty candidate list)"));

    return { summary, tokensUsed: data.usageMetadata?.totalTokenCount };
  },
};
