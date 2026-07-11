// Embedded vector store: an in-memory array of { id, text, metadata, vector,
// contentHash }, persisted to one local JSON file. Deliberately not a real
// vector database (LanceDB/Chroma/pgvector) -- this app's whole knowledge
// base is a few thousand short chunks at most, and a flat cosine-similarity
// scan over that is microseconds, so a dedicated vector DB would only add a
// native/binary dependency for no real benefit at this scale (same "in-memory
// + JSON snapshot" philosophy as server/cache.js and the rolling-history
// modules). If this ever needs to scale past a single process/machine, swap
// this file for a real vector DB client behind the same four functions below
// -- nothing in indexer.js or retriever.js needs to change.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, "..", ".cache");
const STORE_PATH = path.join(STORE_DIR, "rag-index.json");

let entries = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return []; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(entries), "utf-8");
}

/** Current entries keyed by id, for the indexer to diff against (skip re-embedding unchanged chunks). */
export function getAllById() {
  return new Map(entries.map((e) => [e.id, e]));
}

/** Replaces the whole store (the indexer rebuilds the full chunk set each cycle) and persists it. */
export function replaceAll(nextEntries) {
  entries = nextEntries;
  persist();
}

export function size() {
  return entries.length;
}

function cosineSimilarity(a, b) {
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

/** Top-k entries by cosine similarity to `queryVector`, each with its score attached. */
export function search(queryVector, k) {
  return entries
    .map((e) => ({ ...e, score: cosineSimilarity(queryVector, e.vector) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, k);
}
