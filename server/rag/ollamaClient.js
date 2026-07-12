// Shared low-level HTTP plumbing for talking to a local Ollama server --
// embeddings.js and llmClient.js both sit on top of this. Kept separate from
// both so swapping the local LLM runtime later (e.g. llama.cpp's own server,
// vLLM) means rewriting this one file, not touching the RAG pipeline above it.
import { OLLAMA_BASE_URL } from "./config.js";

export class OllamaUnavailableError extends Error {
  constructor(detail) {
    super(`Ollama is not reachable at ${OLLAMA_BASE_URL} -- is it installed and running? (${detail})`);
    this.name = "OllamaUnavailableError";
  }
}

async function request(path, body) {
  let response;
  try {
    response = await fetch(`${OLLAMA_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (error) {
    // ECONNREFUSED (Ollama not running) and DNS failures both land here --
    // this is the "quiet not-configured" case, same shape as every optional
    // keyed connector in this app when its env var is absent.
    throw new OllamaUnavailableError(error.message);
  }

  if (!response.ok) {
    const detail = await response.text().catch(() => response.statusText);
    throw new Error(`Ollama ${path} responded with ${response.status}: ${detail}`);
  }
  return response;
}

/**
 * Non-streaming JSON call (used by embeddings, and by chat when streaming
 * isn't needed, e.g. server/malwareExtraction.js). Ollama's /api/chat
 * defaults to `stream: true` unless told otherwise -- confirmed live that
 * omitting this here made response.json() choke trying to parse a multi-line
 * NDJSON body as one JSON value ("Unexpected non-whitespace character after
 * JSON"). Explicit `stream: false` here means no caller of this function has
 * to remember that per-endpoint default themselves.
 */
export async function ollamaJson(path, body) {
  const response = await request(path, { ...body, stream: false });
  return response.json();
}

/** Streaming call -- Ollama's own stream format is NDJSON (one JSON object per line), not SSE. */
export async function ollamaStream(path, body, onLine) {
  const response = await request(path, { ...body, stream: true });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let newlineIndex;
    while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (line) onLine(JSON.parse(line));
    }
  }
}

/** Cheap reachability + model-presence check for the chat health endpoint -- never throws. */
export async function checkOllamaHealth(requiredModels) {
  try {
    const res = await fetch(`${OLLAMA_BASE_URL}/api/tags`);
    if (!res.ok) return { available: false, missingModels: requiredModels };
    const { models = [] } = await res.json();
    // Ollama lists pulled models as "name:tag" (e.g. "llama3.1:8b"), but a
    // bare name with no tag (e.g. "nomic-embed-text", as .env.example itself
    // tells the user to pull) resolves to ":latest" both when Ollama stores
    // it and when it's called by that bare name -- confirmed live, `ollama
    // pull nomic-embed-text` lists as "nomic-embed-text:latest" in `ollama
    // list`. Match a configured bare name against its ":latest" entry too,
    // or this reports a real, working model as "missing" forever.
    const installed = new Set(models.map((m) => m.name));
    const missingModels = requiredModels.filter((m) => !installed.has(m) && !installed.has(`${m}:latest`));
    return { available: true, missingModels };
  } catch {
    return { available: false, missingModels: requiredModels };
  }
}
