// Orchestrates one chat turn: retrieve -> ground -> generate. This file is
// what actually enforces "answer only using the platform's own
// intelligence" -- retriever.js's similarity threshold decides whether
// there's anything relevant at all, and the system prompt below instructs
// the model to stick to exactly the context it's given, nothing else.
import { retrieve } from "./retriever.js";
import { chatStream } from "./llmClient.js";
import { CHAT_HISTORY_TURNS } from "./config.js";

const SYSTEM_PROMPT =
  "You are the threat intelligence assistant built into this dashboard. " +
  "Answer ONLY using the numbered 'Platform intelligence' context given with each question -- " +
  "never invent CVE IDs, actor names, dates, or figures that aren't in that context. " +
  "If the context doesn't contain enough to answer, say plainly that the platform's current data doesn't cover it. " +
  "Keep answers concise. When you reference a specific fact, mention its label (e.g. the CVE ID or actor name) exactly as given.";

const NO_MATCH_ANSWER =
  "I don't have information about that in the platform's current intelligence. " +
  "Try asking about a specific CVE, threat actor, malware family, or recent ransomware activity.";

function formatContext(chunks) {
  return chunks.map((c, i) => `[${i + 1}] ${c.text}`).join("\n");
}

function toSource(chunk) {
  return { id: chunk.id, type: chunk.metadata.type, label: chunk.metadata.label, url: chunk.metadata.url, score: Math.round(chunk.score * 100) / 100 };
}

/**
 * Answers one question, streaming the reply via `onToken`. `history` is the
 * prior turns of this conversation ([{role, content}, ...]), trimmed to the
 * last few so a small local model's context window stays comfortably sized.
 * Returns the full answer text + the sources actually used, once streaming completes.
 */
export async function answerQuestionStream(question, history, onToken) {
  const chunks = await retrieve(question);

  if (chunks.length === 0) {
    onToken(NO_MATCH_ANSWER);
    return { answer: NO_MATCH_ANSWER, sources: [] };
  }

  const messages = [
    { role: "system", content: SYSTEM_PROMPT },
    ...(history ?? []).slice(-CHAT_HISTORY_TURNS),
    { role: "user", content: `Platform intelligence:\n${formatContext(chunks)}\n\nQuestion: ${question}` },
  ];

  const answer = await chatStream(messages, onToken);
  return { answer, sources: chunks.map(toSource) };
}
