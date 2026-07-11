// Local embedding model client (Ollama's /api/embed, batch-capable). Free,
// no API key -- swap OLLAMA_EMBED_MODEL for any other embedding model Ollama
// can pull without touching anything that calls this file.
import { ollamaJson } from "./ollamaClient.js";
import { OLLAMA_EMBED_MODEL } from "./config.js";

/** Embeds a batch of texts in one request. Order of the returned vectors matches `texts`. */
export async function embedBatch(texts) {
  const { embeddings } = await ollamaJson("/api/embed", { model: OLLAMA_EMBED_MODEL, input: texts });
  return embeddings;
}

/** Embeds a single text (e.g. the user's question at query time). */
export async function embedOne(text) {
  const [vector] = await embedBatch([text]);
  return vector;
}
