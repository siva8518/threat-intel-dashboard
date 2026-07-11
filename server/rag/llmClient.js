// Local chat model client (Ollama's /api/chat, streamed). Free, no API key --
// swap OLLAMA_CHAT_MODEL for any other instruct model Ollama can pull without
// touching ragChat.js or the route above it.
import { ollamaStream } from "./ollamaClient.js";
import { OLLAMA_CHAT_MODEL } from "./config.js";

/** Streams the assistant's reply token-by-token via `onToken`, returning the full accumulated text. */
export async function chatStream(messages, onToken) {
  let full = "";
  await ollamaStream("/api/chat", { model: OLLAMA_CHAT_MODEL, messages }, (line) => {
    const token = line.message?.content ?? "";
    if (token) {
      full += token;
      onToken(token);
    }
  });
  return full;
}
