// Anthropic's implementation of the shared AIProvider shape every
// server/ai/providers/*.js file exposes -- summarize() plain-text,
// summarizeJson() forcing a JSON-only response via prompting (Anthropic's
// Messages API has no OpenAI-style `response_format: json_object` toggle,
// but every caller of summarizeJson() in this app already regex-extracts
// the first `{...}` block from the returned text rather than trusting a
// strict content-type -- see e.g. server/investigation/correlationSummary.js's
// parseModelReport -- so a strong system-prompt instruction is sufficient
// and consistent with how huggingFaceProvider.js/togetherProvider.js's
// best-effort JSON mode already works here).
//
// Distinct request/response shape from every other provider in this
// directory: `x-api-key`/`anthropic-version` headers (not Bearer auth),
// `system` as a top-level field (not a "system" message), and a
// `content: [{type: "text", text}]` array response (not `choices[0].message`).
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const BASE_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_TOKENS = 8_192;
const LABEL = "Anthropic";

const JSON_ONLY_INSTRUCTION = "\n\nRespond with ONLY the raw JSON object -- no markdown code fences, no prose before or after it.";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callAnthropic(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.anthropic;
  const model = tier === "fast" ? fastModel : defaultModel;
  const system = jsonMode ? `${systemPrompt ?? ""}${JSON_ONLY_INSTRUCTION}` : systemPrompt;

  let data;
  try {
    data = await fetchJson(BASE_URL, {
      source: LABEL,
      method: "POST",
      headers: { "x-api-key": apiKey, "anthropic-version": ANTHROPIC_VERSION, "content-type": "application/json" },
      body: JSON.stringify({
        model,
        max_tokens: MAX_TOKENS,
        ...(system ? { system } : {}),
        messages: [{ role: "user", content: prompt }],
        ...(temperature !== undefined ? { temperature } : {}),
      }),
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    throw classifyProviderError(LABEL, error);
  }

  const summary = data.content?.find((block) => block.type === "text")?.text;
  if (!summary) throw classifyProviderError(LABEL, new Error("Anthropic returned no usable content"));

  const tokensUsed = data.usage ? (data.usage.input_tokens ?? 0) + (data.usage.output_tokens ?? 0) : undefined;
  return { summary, model, tokensUsed };
}

export const anthropicProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.anthropic.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.anthropic.apiKey);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callAnthropic(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callAnthropic(userPrompt, { ...options, jsonMode: true });
  },
};
