// Question -> top-k relevant chunks. The similarity threshold is the actual
// enforcement of "only answer from platform intelligence": if nothing in the
// index is a strong enough match, this returns an empty list and ragChat.js
// never even calls the LLM, rather than trusting a prompt instruction alone.
import { embedOne } from "./embeddings.js";
import * as vectorStore from "./vectorStore.js";
import { RAG_TOP_K, RAG_SIMILARITY_THRESHOLD } from "./config.js";

const CVE_ID_PATTERN = /CVE-\d{4}-\d{4,7}/gi;

/**
 * Exact-id lookups for any CVE ID literally named in the question --
 * confirmed live that semantic embedding similarity, which is scoring
 * "what's related to this topic," can miss the one chunk that's an exact
 * match for a specific CVE number even when that chunk is indexed. A CVE ID
 * mentioned by name is an unambiguous signal a keyword/id lookup handles
 * better than embeddings ever will, so this checks the vector store directly
 * by id first (both the plain NVD record and the KEV catalog entry, since
 * the same CVE can exist as both), then falls back to a substring scan of
 * every indexed chunk's own text -- this is what makes a question like
 * "which actors exploit CVE-2025-XXXX" reliably surface a threat-actor
 * chunk that names that CVE (server/threatActorIntelligence.js's
 * `cveExploited` field), not just the CVE's own record, since embeddings
 * alone aren't guaranteed to weight an exact numeric id token that highly.
 */
function findExactCveMatches(question) {
  const ids = [...new Set((question.match(CVE_ID_PATTERN) ?? []).map((id) => id.toUpperCase()))];
  if (ids.length === 0) return [];

  const byId = vectorStore.getAllById();
  const matches = [];
  const seenIds = new Set();
  for (const id of ids) {
    for (const prefix of ["cve", "kev"]) {
      const entry = byId.get(`${prefix}:${id}`);
      if (entry && !seenIds.has(entry.id)) {
        matches.push({ ...entry, score: 1 });
        seenIds.add(entry.id);
      }
    }
  }
  for (const entry of byId.values()) {
    if (seenIds.has(entry.id)) continue;
    if (ids.some((id) => entry.text.toUpperCase().includes(id))) {
      matches.push({ ...entry, score: 1 });
      seenIds.add(entry.id);
    }
  }
  return matches;
}

export async function retrieve(question, { k = RAG_TOP_K, threshold = RAG_SIMILARITY_THRESHOLD } = {}) {
  const exactMatches = findExactCveMatches(question);
  const queryVector = await embedOne(question);
  const semanticMatches = vectorStore.search(queryVector, k).filter((entry) => entry.score >= threshold);

  // Exact matches always win a slot; semantic results fill whatever's left,
  // skipping anything already covered by an exact match.
  const seenIds = new Set(exactMatches.map((e) => e.id));
  return [...exactMatches, ...semanticMatches.filter((e) => !seenIds.has(e.id))].slice(0, k);
}
