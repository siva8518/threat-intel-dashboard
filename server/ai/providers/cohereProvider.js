// Cohere Command R via Cohere's v2 chat API. NOTE: unlike this project's
// other connectors/lookups (which are always confirmed against a live
// response before being considered done), this file was written from
// Cohere's published API docs with no live key available to test against --
// double-check the response shape below against a real call once
// COHERE_API_KEY is set, same as any other integration in this codebase
// would get verified.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.cohere.com/v2/chat";
const REQUEST_TIMEOUT_MS = 30_000;
const LABEL = "Cohere";

export const cohereProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.cohere.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.cohere.apiKey);
  },

  /** @param {string} prompt @returns {Promise<{summary: string, tokensUsed?: number}>} */
  async summarize(prompt) {
    const { apiKey, model } = AI_ROUTER_CONFIG.cohere;
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

    // Cohere v2's chat response nests text inside a content-block array
    // (the same "array of typed content parts" shape Anthropic/OpenAI's
    // newer APIs use) -- find the first text block rather than assuming
    // index 0 is always text, in case a response ever includes other block
    // types (tool calls, thinking blocks, etc.) first.
    const textBlock = data.message?.content?.find((block) => block.type === "text");
    const summary = textBlock?.text;
    if (!summary) throw classifyProviderError(LABEL, new Error("Cohere returned no usable text content"));

    return { summary, tokensUsed: data.usage?.tokens?.output_tokens };
  },
};
