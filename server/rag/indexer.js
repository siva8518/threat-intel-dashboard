// Keeps the vector store in sync with the platform's own data. Runs on the
// same "boot immediately, then every intervalMs forever" schedule as every
// connector in server/scheduler.js -- deliberately separate from that
// scheduler (indexing depends on the connectors' cache already being warm,
// and needs its own embed/hash bookkeeping), not a fork of it.
import crypto from "node:crypto";
import { buildChunks } from "./chunkBuilder.js";
import { embedBatch } from "./embeddings.js";
import * as vectorStore from "./vectorStore.js";
import { OllamaUnavailableError } from "./ollamaClient.js";
import { EMBED_BATCH_SIZE, RAG_INDEX_INTERVAL_MS } from "./config.js";
import { log } from "../lib/log.js";

function hashText(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

/**
 * Rebuilds the index: chunks unchanged since the last cycle (same id, same
 * content hash) keep their existing embedding; only new or edited chunks are
 * re-embedded. Chunks no longer present (e.g. an expired CVE window, a
 * resolved campaign) are dropped since the store is fully replaced each cycle.
 */
export async function buildIndex() {
  const chunks = buildChunks();
  const existingById = vectorStore.getAllById();

  const toEmbed = [];
  const nextEntries = [];

  for (const chunk of chunks) {
    const contentHash = hashText(chunk.text);
    const existing = existingById.get(chunk.id);
    if (existing && existing.contentHash === contentHash) {
      nextEntries.push(existing);
    } else {
      toEmbed.push({ ...chunk, contentHash });
    }
  }

  for (let i = 0; i < toEmbed.length; i += EMBED_BATCH_SIZE) {
    const batch = toEmbed.slice(i, i + EMBED_BATCH_SIZE);
    const vectors = await embedBatch(batch.map((c) => c.text));
    batch.forEach((c, j) => nextEntries.push({ ...c, vector: vectors[j] }));
  }

  vectorStore.replaceAll(nextEntries);
  log.info("rag-indexer", `index rebuilt: ${nextEntries.length} chunks (${toEmbed.length} newly embedded, ${nextEntries.length - toEmbed.length} unchanged)`);
}

let hasWarnedUnavailable = false;

async function runCycle() {
  try {
    await buildIndex();
    hasWarnedUnavailable = false;
  } catch (error) {
    if (error instanceof OllamaUnavailableError) {
      // Quiet after the first warning per outage -- this fires every cycle
      // otherwise, and the chat route/health check already surface this to
      // the user; no need to spam the server log every 15 minutes.
      if (!hasWarnedUnavailable) {
        log.warn("rag-indexer", `${error.message} -- the chatbot will report itself unavailable until Ollama is running.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("rag-indexer", `index build failed: ${error.message}`);
    }
  }
}

/** Delayed first run so the connectors' own first sync (see server/index.js) has a chance to populate the cache. */
export function startRagIndexer() {
  setTimeout(runCycle, 10_000);
  setInterval(runCycle, RAG_INDEX_INTERVAL_MS);
}
