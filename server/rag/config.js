// Central tunables for the local RAG chatbot, same "one place, not magic
// numbers scattered around" philosophy as src/config/constants.ts on the
// frontend. Every one of these is free to change without touching any other
// file in server/rag/.
export const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL ?? "http://localhost:11434";

// Small, free, CPU-friendly instruct models -- good enough for "synthesize
// these 5 retrieved chunks," which is all the generation step ever has to do.
export const OLLAMA_CHAT_MODEL = process.env.OLLAMA_CHAT_MODEL ?? "llama3.1:8b";
export const OLLAMA_EMBED_MODEL = process.env.OLLAMA_EMBED_MODEL ?? "nomic-embed-text";

// A separate AI_SUMMARY_MODEL was tried here so server/aiThreatSummary.js
// could use a smaller/faster model than the RAG chatbot/combinedExtraction.js
// share. Reverted -- confirmed live on this machine's tight free-memory
// headroom (~2GB), running two different models meant Ollama constantly
// evicting/reloading between them, adding 7+ seconds of load time to a
// literally one-word test call. Net effect was slower and less reliable
// (intermittent "fetch failed" errors), not faster. Keep everything on one
// shared model unless this machine gets meaningfully more free RAM.
export const RAG_TOP_K = Number(process.env.RAG_TOP_K) || 6;

// Cosine similarity is in [-1, 1]; nomic-embed-text's real-world scores for
// genuinely relevant matches cluster well above this. Below it, the question
// isn't actually about anything in the platform's data -- answer "I don't
// know" instead of feeding the LLM weak/irrelevant context it might paper
// over with a hallucinated-sounding answer.
export const RAG_SIMILARITY_THRESHOLD = Number(process.env.RAG_SIMILARITY_THRESHOLD) || 0.45;

export const RAG_INDEX_INTERVAL_MS = Number(process.env.RAG_INDEX_INTERVAL_MS) || 15 * 60 * 1000; // 15 min, matches every other connector's cadence

// How many chunks are embedded per Ollama /api/embed call. Batching is a
// single HTTP round-trip for many texts instead of one per chunk -- Ollama
// itself still processes them one at a time on CPU, but this removes
// thousands of redundant HTTP round-trips on a full rebuild.
export const EMBED_BATCH_SIZE = 32;

// Per-source caps on the indexing pipeline, not the dashboard itself -- keeps
// a full rebuild to a bounded, predictable number of embed calls even when a
// source's raw feed is huge (KEV's all-time catalog, MalwareBazaar sightings).
export const MAX_CHUNKS_PER_SOURCE = {
  cve: 300,
  kev: 300,
  ransomware: 250,
  news: 200,
  actors: 300, // MITRE ATT&CK's full Groups list is ~180 today; headroom, not a real cap
  malware: 60,
  techniques: 250,
  campaigns: 60,
  darkweb: 60,
};

export const CHAT_HISTORY_TURNS = 6; // last N messages (both roles) sent as context, bounding prompt size for a small local model
