import { Router } from "express";
import { checkOllamaHealth, OllamaUnavailableError } from "../rag/ollamaClient.js";
import { OLLAMA_CHAT_MODEL, OLLAMA_EMBED_MODEL } from "../rag/config.js";
import * as vectorStore from "../rag/vectorStore.js";
import { answerQuestionStream } from "../rag/ragChat.js";
import { log } from "../lib/log.js";

export const router = Router();

// Lets the frontend show a real "install Ollama" / "pull these models" state
// instead of a generic broken-chat error -- same "quiet not-configured, not
// a failure" UX this app already uses for every optional keyed source.
router.get("/chat/health", async (_req, res) => {
  const { available, missingModels } = await checkOllamaHealth([OLLAMA_CHAT_MODEL, OLLAMA_EMBED_MODEL]);
  res.json({
    ollamaAvailable: available,
    missingModels,
    indexedChunks: vectorStore.size(),
    chatModel: OLLAMA_CHAT_MODEL,
    embedModel: OLLAMA_EMBED_MODEL,
  });
});

// Server-Sent Events, not a single JSON response -- the reply is streamed
// token-by-token as the local model generates it, same as any modern chat
// UI, followed by one "sources" event once retrieval is known and a final
// "done". A plain POST (not GET+EventSource) since the message body can be
// arbitrarily long; the frontend reads this with fetch + a manual reader,
// not the browser's built-in EventSource (which can't POST).
router.post("/chat", async (req, res) => {
  const { message, history } = req.body ?? {};
  if (!message || typeof message !== "string") {
    return res.status(400).json({ error: "message is required" });
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  const send = (type, data) => res.write(`data: ${JSON.stringify({ type, ...data })}\n\n`);

  try {
    const { sources } = await answerQuestionStream(message, history, (text) => send("token", { text }));
    send("sources", { sources });
    send("done", {});
  } catch (error) {
    const notConfigured = error instanceof OllamaUnavailableError;
    if (!notConfigured) log.error("chat", `chat turn failed: ${error.message}`);
    send("error", { message: error.message, notConfigured });
  } finally {
    res.end();
  }
});
