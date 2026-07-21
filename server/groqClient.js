// Thin client for Groq's free-tier hosted inference (OpenAI-compatible chat
// completions API) -- used only by server/aiThreatSummary.js, swapped in for
// the local Ollama call that job used to make. Ollama's own recurring
// "Stopping..." deadlock (see server/rag/ollamaClient.js) hit this
// specific job hardest, since it's this app's single heaviest LLM call
// (25+ section structured report, largest prompt+completion of anything
// here) -- moving just this one call off the local model onto a free
// hosted API sidesteps that whole class of problem for it, while
// server/combinedExtraction.js and the RAG chatbot stay on local Ollama
// (untouched, out of scope for this change).
import { ApiError, fetchJson } from "./lib/http.js";

const GROQ_BASE_URL = "https://api.groq.com/openai/v1";
const REQUEST_TIMEOUT_MS = 60_000;

export class GroqUnavailableError extends Error {
  constructor(detail) {
    super(`Groq is not reachable or not usable right now (${detail})`);
    this.name = "GroqUnavailableError";
  }
}

/**
 * Chat completion, JSON-object response format. Mirrors
 * server/rag/ollamaClient.js#ollamaJson's return shape ({message: {content}})
 * so aiThreatSummary.js's existing `response.message?.content` parsing needed
 * no changes beyond the import/call site itself.
 */
export async function groqJson({ model, messages, temperature }) {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    throw new GroqUnavailableError("GROQ_API_KEY is not set -- get a free key at https://console.groq.com/keys and add it to .env");
  }

  let data;
  try {
    data = await fetchJson(`${GROQ_BASE_URL}/chat/completions`, {
      source: "Groq",
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model, messages, temperature, response_format: { type: "json_object" } }),
      timeoutMs: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    if (error instanceof ApiError) {
      // 429 (free-tier rate limit) is the one status worth treating like an
      // outage rather than "this one article failed" -- every other article
      // still queued in the same batch would hit the identical limit right
      // behind it, same reasoning as OllamaUnavailableError stopping the
      // whole cycle in server/aiThreatSummaryJob.js rather than burning
      // through the rest of the batch one-by-one failure at a time.
      if (error.status === 429) throw new GroqUnavailableError("rate limited -- free-tier request/token limit reached, try again shortly");
      throw new GroqUnavailableError(error.message);
    }
    throw error;
  }

  const content = data.choices?.[0]?.message?.content ?? "";
  return { message: { content } };
}
