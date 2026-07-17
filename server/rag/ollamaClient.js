// Shared low-level HTTP plumbing for talking to a local Ollama server --
// embeddings.js and llmClient.js both sit on top of this. Kept separate from
// both so swapping the local LLM runtime later (e.g. llama.cpp's own server,
// vLLM) means rewriting this one file, not touching the RAG pipeline above it.
import { OLLAMA_BASE_URL } from "./config.js";
import { recordOllamaFailure, recordOllamaSuccess } from "./ollamaWatchdog.js";

export class OllamaUnavailableError extends Error {
  constructor(detail) {
    super(`Ollama is not reachable at ${OLLAMA_BASE_URL} -- is it installed and running? (${detail})`);
    this.name = "OllamaUnavailableError";
  }
}

// fetch() here previously had no timeout at all -- confirmed live that a
// model wedged in Ollama's own "Stopping..." unload deadlock (recurs on
// this machine every so often, a bug in Ollama itself, not this app) hung
// an in-flight request forever with no error and no response. Both
// server/aiThreatSummaryJob.js and server/combinedExtractionJob.js are
// self-rescheduling only after their current cycle settles (to guarantee
// exactly one cycle in flight at a time -- see their own loop() comments),
// so an unbounded hang here didn't just fail one request, it permanently
// froze the entire job loop with zero log output until someone noticed
// hours later and restarted Ollama by hand. Aborting after this long
// converts that silent freeze back into the OllamaUnavailableError path
// every caller (both jobs, the chat route) already handles: dedup-logged
// once, cycle retried next interval.
const REQUEST_TIMEOUT_MS = 120_000;

// Serializes every call through this file -- confirmed via ollama/ollama
// issue #14364 that Ollama can wedge into the same permanent "Stopping..."
// deadlock this file otherwise works around when two independent processes
// send it concurrent chat requests at once. This app has exactly that shape:
// aiThreatSummaryJob.js and combinedExtractionJob.js both run on a 2min
// cycle only ~10s apart, each generation call commonly takes 20-40s+, and
// the chat route can fire at any time on top of that -- their requests were
// very plausibly overlapping in-flight on most cycles. A simple
// promise-chain queue means this whole app never has more than one Ollama
// request in flight at a time, sidestepping the trigger entirely rather
// than reacting to it after the fact. queueTail always resolves (even when
// the queued call itself rejects) so one failed call never blocks everyone
// waiting behind it.
let queueTail = Promise.resolve();

function withOllamaQueue(fn) {
  const result = queueTail.then(fn, fn);
  queueTail = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function createTimeoutController(ms) {
  const controller = new AbortController();
  let timer = setTimeout(() => controller.abort(), ms);
  return {
    signal: controller.signal,
    // Called after each chunk of a streamed response arrives, so a
    // slow-but-actively-generating reply isn't cut off mid-stream -- only a
    // genuine stall (no bytes at all for the full window, including the
    // wait for the very first byte) trips the abort.
    poke() {
      clearTimeout(timer);
      timer = setTimeout(() => controller.abort(), ms);
    },
    clear() {
      clearTimeout(timer);
    },
  };
}

async function request(path, body) {
  const timeout = createTimeoutController(REQUEST_TIMEOUT_MS);
  let response;
  try {
    response = await fetch(`${OLLAMA_BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // keep_alive: -1 tells Ollama to never auto-unload this model after
      // idle time -- confirmed live that the repeated "Stopping..." deadlock
      // this file works around (see REQUEST_TIMEOUT_MS and
      // ollamaWatchdog.js) recurred on a strikingly regular ~4min cadence,
      // matching Ollama's own idle-unload timer rather than random load
      // contention. That auto-unload path is what appears to wedge, so
      // skipping it entirely addresses the actual trigger, not just the
      // symptom. The timeout + watchdog stay in place regardless, in case
      // this doesn't fully eliminate it.
      body: JSON.stringify({ ...body, keep_alive: -1 }),
      signal: timeout.signal,
    });
  } catch (error) {
    timeout.clear();
    // ECONNREFUSED (Ollama not running) and DNS failures both land here,
    // same as an aborted-for-timeout request -- all three mean "Ollama
    // isn't usable right now," the "quiet not-configured" case, same shape
    // as every optional keyed connector in this app when its env var is
    // absent. Reported to the watchdog either way -- if Ollama really is
    // just not installed, restarting a process that doesn't exist is a
    // harmless no-op (see ollamaWatchdog.js's own error handling).
    recordOllamaFailure();
    const detail = error.name === "AbortError" ? `no response within ${REQUEST_TIMEOUT_MS / 1000}s -- Ollama may be stuck` : error.message;
    throw new OllamaUnavailableError(detail);
  }

  if (!response.ok) {
    timeout.clear();
    const detail = await response.text().catch(() => response.statusText);
    throw new Error(`Ollama ${path} responded with ${response.status}: ${detail}`);
  }
  return { response, timeout };
}

/**
 * Non-streaming JSON call (used by embeddings, and by chat when streaming
 * isn't needed, e.g. server/malwareExtraction.js). Ollama's /api/chat
 * defaults to `stream: true` unless told otherwise -- confirmed live that
 * omitting this here made response.json() choke trying to parse a multi-line
 * NDJSON body as one JSON value ("Unexpected non-whitespace character after
 * JSON"). Explicit `stream: false` here means no caller of this function has
 * to remember that per-endpoint default themselves.
 */
export async function ollamaJson(path, body) {
  return withOllamaQueue(async () => {
    const { response, timeout } = await request(path, { ...body, stream: false });
    try {
      const json = await response.json();
      recordOllamaSuccess();
      return json;
    } catch (error) {
      if (error.name === "AbortError") {
        recordOllamaFailure();
        throw new OllamaUnavailableError(`no response within ${REQUEST_TIMEOUT_MS / 1000}s -- Ollama may be stuck`);
      }
      throw error;
    } finally {
      timeout.clear();
    }
  });
}

/** Streaming call -- Ollama's own stream format is NDJSON (one JSON object per line), not SSE. */
export async function ollamaStream(path, body, onLine) {
  return withOllamaQueue(async () => {
    const { response, timeout } = await request(path, { ...body, stream: true });
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        timeout.poke();
        buffer += decoder.decode(value, { stream: true });

        let newlineIndex;
        while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
          const line = buffer.slice(0, newlineIndex).trim();
          buffer = buffer.slice(newlineIndex + 1);
          if (line) onLine(JSON.parse(line));
        }
      }
      recordOllamaSuccess();
    } catch (error) {
      if (error.name === "AbortError") {
        recordOllamaFailure();
        throw new OllamaUnavailableError(`stream stalled with no data for ${REQUEST_TIMEOUT_MS / 1000}s -- Ollama may be stuck`);
      }
      throw error;
    } finally {
      timeout.clear();
    }
  });
}

/** Cheap reachability + model-presence check for the chat health endpoint -- never throws. */
export async function checkOllamaHealth(requiredModels) {
  try {
    const res = await fetch(`${OLLAMA_BASE_URL}/api/tags`);
    if (!res.ok) return { available: false, missingModels: requiredModels };
    const { models = [] } = await res.json();
    // Ollama lists pulled models as "name:tag" (e.g. "llama3.1:8b"), but a
    // bare name with no tag (e.g. "nomic-embed-text", as .env.example itself
    // tells the user to pull) resolves to ":latest" both when Ollama stores
    // it and when it's called by that bare name -- confirmed live, `ollama
    // pull nomic-embed-text` lists as "nomic-embed-text:latest" in `ollama
    // list`. Match a configured bare name against its ":latest" entry too,
    // or this reports a real, working model as "missing" forever.
    const installed = new Set(models.map((m) => m.name));
    const missingModels = requiredModels.filter((m) => !installed.has(m) && !installed.has(`${m}:latest`));
    return { available: true, missingModels };
  } catch {
    return { available: false, missingModels: requiredModels };
  }
}
