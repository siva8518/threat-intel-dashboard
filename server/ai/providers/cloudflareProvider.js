// Cloudflare Workers AI -- the one provider in this app with its own
// request/response envelope instead of the OpenAI chat shape every other
// provider here uses, and the only one needing a 2nd credential (account
// ID, not just a bearer token). Endpoint: POST .../accounts/{accountId}/ai/run/{model}.
// Response body is {success, result: {response, usage?}, errors: [...]}
// rather than an HTTP error code for every failure mode -- a request can
// come back 200 OK with success:false, which is handled explicitly below.
import { fetchJson } from "../../lib/http.js";
import { classifyProviderError } from "../aiProviderError.js";
import { AI_ROUTER_CONFIG } from "../config.js";

const REQUEST_TIMEOUT_MS = 60_000;
const LABEL = "Cloudflare Workers AI";

/**
 * @param {string} prompt
 * @param {{systemPrompt?: string, temperature?: number, jsonMode?: boolean, tier?: "fast"}} options
 */
async function callCloudflare(prompt, { systemPrompt, temperature, jsonMode = false, tier } = {}) {
  const { apiKey, accountId, model: defaultModel, fastModel } = AI_ROUTER_CONFIG.cloudflare;
  const model = tier === "fast" ? fastModel : defaultModel;
  const messages = systemPrompt ? [{ role: "system", content: systemPrompt }, { role: "user", content: prompt }] : [{ role: "user", content: prompt }];
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/${model}`;

  let data;
  try {
    data = await fetchJson(url, {
      source: LABEL,
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        messages,
        ...(temperature !== undefined ? { temperature } : {}),
        ...(jsonMode ? { response_format: { type: "json_object" } } : {}),
      }),
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    throw classifyProviderError(LABEL, error);
  }

  // Cloudflare can return HTTP 200 with success:false (invalid model,
  // account-level issue, etc.) -- fetchJson's !response.ok check never
  // catches this, so it's checked explicitly here.
  if (data?.success === false) {
    const detail = data.errors?.map((e) => e.message).join("; ") || "unknown error";
    throw classifyProviderError(LABEL, new Error(detail));
  }

  const summary = data?.result?.response;
  if (!summary) throw classifyProviderError(LABEL, new Error("Cloudflare Workers AI returned no usable content"));

  const usage = data.result?.usage;
  return { summary, model, tokensUsed: usage?.total_tokens };
}

export const cloudflareProvider = {
  label: LABEL,
  model: AI_ROUTER_CONFIG.cloudflare.model,

  isConfigured() {
    return Boolean(AI_ROUTER_CONFIG.cloudflare.apiKey && AI_ROUTER_CONFIG.cloudflare.accountId);
  },

  /**
   * @param {string} prompt
   * @param {{tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarize(prompt, options = {}) {
    return callCloudflare(prompt, options);
  },

  /**
   * @param {string} userPrompt
   * @param {{systemPrompt?: string, temperature?: number, tier?: "fast"}} [options]
   * @returns {Promise<{summary: string, model: string, tokensUsed?: number}>}
   */
  async summarizeJson(userPrompt, options = {}) {
    return callCloudflare(userPrompt, { ...options, jsonMode: true });
  },
};
