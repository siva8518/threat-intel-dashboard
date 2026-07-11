import { useEffect, useRef, useState } from "react";
import { Bot, Send, Square, Terminal, User } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { useChatHealth } from "@/hooks/useChatHealth";
import { streamChat } from "@/api/chatApi";
import type { ChatMessage, ChatSource } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

interface DisplayMessage extends ChatMessage {
  sources?: ChatSource[];
  isError?: boolean;
}

const SOURCE_TYPE_LABEL: Record<ChatSource["type"], string> = {
  cve: "CVE",
  kev: "KEV",
  ransomware: "Ransomware",
  actor: "Actor",
  technique: "ATT&CK",
  malware: "Malware",
  news: "News",
};

/** Fully local RAG chatbot -- see server/rag/. Answers are grounded only in this platform's own synced intelligence (server/rag/chunkBuilder.js); nothing is sent to any external/paid API. */
export function Chatbot() {
  const { data: health, isLoading, isError } = useChatHealth();
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const cancelRef = useRef<(() => void) | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => () => cancelRef.current?.(), []);

  function send(e: React.FormEvent) {
    e.preventDefault();
    const question = draft.trim();
    if (!question || isStreaming) return;

    const history: ChatMessage[] = messages.map(({ role, content }) => ({ role, content }));
    setMessages((prev) => [...prev, { role: "user", content: question }, { role: "assistant", content: "" }]);
    setDraft("");
    setIsStreaming(true);

    cancelRef.current = streamChat(question, history, {
      onToken: (text) => {
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = { ...next[next.length - 1], content: next[next.length - 1].content + text };
          return next;
        });
      },
      onSources: (sources) => {
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = { ...next[next.length - 1], sources };
          return next;
        });
      },
      onError: (message, notConfigured) => {
        setMessages((prev) => {
          const next = [...prev];
          next[next.length - 1] = {
            ...next[next.length - 1],
            content: notConfigured ? "Ollama isn't running right now, so I can't answer. Start it and try again." : `Something went wrong: ${message}`,
            isError: true,
          };
          return next;
        });
        setIsStreaming(false);
      },
      onDone: () => setIsStreaming(false),
    });
  }

  function stop() {
    cancelRef.current?.();
    setIsStreaming(false);
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Bot className="h-4 w-4 text-primary" />
          AI Assistant <span className="font-normal text-muted">(local &amp; free -- answers only from this platform's data)</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-72 w-full" />
        ) : isError || !health ? (
          <ErrorState message="Couldn't reach the chat backend right now." />
        ) : !health.ollamaAvailable ? (
          <SetupNotice chatModel={health.chatModel} embedModel={health.embedModel} />
        ) : health.missingModels.length > 0 ? (
          <SetupNotice chatModel={health.chatModel} embedModel={health.embedModel} missingModels={health.missingModels} />
        ) : (
          <div className="flex h-[28rem] flex-col">
            <div className="flex-1 space-y-4 overflow-y-auto pr-1">
              {messages.length === 0 && (
                <p className="py-10 text-center text-sm text-muted">
                  Ask about a CVE, threat actor, malware family, or recent ransomware activity -- answers are grounded in{" "}
                  {health.indexedChunks.toLocaleString()} indexed pieces of this platform's own intelligence.
                </p>
              )}
              {messages.map((m, i) => (
                <MessageBubble key={i} message={m} />
              ))}
              <div ref={bottomRef} />
            </div>

            <form onSubmit={send} className="mt-3 flex gap-2 border-t border-white/[0.06] pt-3">
              <Input
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="Ask about this platform's threat intelligence…"
                disabled={isStreaming}
                className="flex-1"
              />
              {isStreaming ? (
                <Button type="button" variant="outline" onClick={stop}>
                  <Square className="h-3.5 w-3.5" />
                  Stop
                </Button>
              ) : (
                <Button type="submit" disabled={!draft.trim()}>
                  <Send className="h-3.5 w-3.5" />
                  Send
                </Button>
              )}
            </form>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function MessageBubble({ message }: { message: DisplayMessage }) {
  const isUser = message.role === "user";
  return (
    <div className={cn("flex gap-2", isUser && "flex-row-reverse")}>
      <div
        className={cn(
          "flex h-7 w-7 shrink-0 items-center justify-center rounded-full border",
          isUser ? "border-primary/30 bg-primary/10 text-primary" : "border-white/10 bg-white/[0.04] text-muted",
        )}
      >
        {isUser ? <User className="h-3.5 w-3.5" /> : <Bot className="h-3.5 w-3.5" />}
      </div>
      <div className={cn("max-w-[85%] space-y-1.5", isUser && "items-end text-right")}>
        <div
          className={cn(
            "rounded-xl px-3 py-2 text-sm",
            isUser ? "bg-primary/15 text-foreground" : message.isError ? "border border-high/30 bg-high/10 text-high" : "border border-white/[0.06] bg-white/[0.03] text-foreground",
          )}
        >
          {message.content || <span className="text-muted">…</span>}
        </div>
        {message.sources && message.sources.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {message.sources.map((s) => (
              <a
                key={s.id}
                href={s.url ?? undefined}
                target="_blank"
                rel="noopener noreferrer"
                title={`Relevance: ${Math.round(s.score * 100)}%`}
                className={cn(
                  "rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-xs text-muted transition-colors",
                  s.url && "hover:border-primary/40 hover:text-foreground",
                )}
              >
                {SOURCE_TYPE_LABEL[s.type]} · {s.label}
              </a>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SetupNotice({ chatModel, embedModel, missingModels }: { chatModel: string; embedModel: string; missingModels?: string[] }) {
  return (
    <div className="flex flex-col items-center gap-3 py-10 text-center text-sm">
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-white/10 bg-white/[0.04]">
        <Terminal className="h-5 w-5 text-muted" />
      </div>
      <p className="max-w-md text-muted">
        {missingModels
          ? `Ollama is running, but ${missingModels.length === 1 ? "a model is" : "some models are"} missing.`
          : "The chatbot needs a local Ollama install -- it's free, runs entirely on this machine, and needs no API key."}
      </p>
      <div className="w-full max-w-md space-y-1.5 rounded-lg border border-white/10 bg-white/[0.03] p-3 text-left font-mono text-xs text-foreground">
        {!missingModels && <p># 1. Install Ollama: https://ollama.com/download</p>}
        {(missingModels ?? [chatModel, embedModel]).map((m) => (
          <p key={m}>ollama pull {m}</p>
        ))}
      </div>
      <p className="text-xs text-muted">This page rechecks automatically every 30 seconds.</p>
    </div>
  );
}
