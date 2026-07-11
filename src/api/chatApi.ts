import { fetchJson } from "@/lib/http";
import type { ChatHealth, ChatMessage, ChatSource } from "@/types/threat-intel";

// Separate from dashboardApi.ts: every other endpoint there is a plain
// fetch-and-parse-JSON call, but /api/chat is a Server-Sent Events stream
// (server/routes/chat.js) read with a raw fetch + manual reader, not
// fetchJson -- different enough shape to earn its own file.

export async function fetchChatHealth(): Promise<ChatHealth> {
  return fetchJson("/api/chat/health", { source: "Chat API" });
}

interface ChatStreamHandlers {
  onToken: (text: string) => void;
  onSources: (sources: ChatSource[]) => void;
  onError: (message: string, notConfigured: boolean) => void;
  onDone: () => void;
}

/** Streams one chat turn. Returns a cancel function (aborts the in-flight request). */
export function streamChat(message: string, history: ChatMessage[], handlers: ChatStreamHandlers): () => void {
  const controller = new AbortController();

  (async () => {
    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, history }),
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        handlers.onError(`Chat request failed (${response.status})`, false);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let boundary: number;
        while ((boundary = buffer.indexOf("\n\n")) !== -1) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const dataLine = frame.split("\n").find((line) => line.startsWith("data: "));
          if (!dataLine) continue;

          const payload = JSON.parse(dataLine.slice(6));
          if (payload.type === "token") handlers.onToken(payload.text);
          else if (payload.type === "sources") handlers.onSources(payload.sources);
          else if (payload.type === "error") handlers.onError(payload.message, payload.notConfigured);
          else if (payload.type === "done") handlers.onDone();
        }
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") return;
      handlers.onError((error as Error).message, false);
    }
  })();

  return () => controller.abort();
}
