// Structured, rolling AI-request telemetry -- same load/append/cap/persist
// pattern as server/sourceReliabilityHistory.js and every entity intelligence
// store (server/threatActorIntelligence.js etc.), just per-request instead
// of per-day. Exists to eventually answer "how many tokens is this platform
// consuming" and "which provider/task is used most" -- see aiRouter.js,
// the only writer, and the ai-usage dashboard route, the only reader besides
// this file's own rollup helper.
//
// Deliberately does NOT log prompts, responses, API keys, or any other
// request/response content -- only the normalized {provider, model, task,
// status, latency, tokens, error reason} shape, matching this app's existing
// "don't log secrets or proprietary content" convention.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// This file lives in server/ai/, one level below every other store that
// uses this same .cache convention (they live directly in server/) --
// go up one level so this shares the existing server/.cache/ directory
// instead of creating a second, disconnected one.
const STORE_DIR = path.join(__dirname, "..", ".cache");
const STORE_PATH = path.join(STORE_DIR, "ai-request-log.json");
const MAX_ENTRIES = 2000;

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

/**
 * @param {{task?: string, provider: string, model?: string, status: "success"|"failure", latencyMs: number, inputTokens?: number, outputTokens?: number, totalTokens?: number, errorReason?: string, fallbackUsed?: boolean, cacheHit?: boolean}} record
 */
export function recordAiRequest(record) {
  entries.push({ timestamp: new Date().toISOString(), ...record });
  if (entries.length > MAX_ENTRIES) entries = entries.slice(-MAX_ENTRIES);
  persist();
}

/** Most recent `limit` entries, newest first -- for a raw activity view if ever needed. */
export function getRecentAiRequests(limit = 100) {
  return entries.slice(-limit).reverse();
}

/**
 * Rolls the log up into per-provider and per-task totals (request counts,
 * success/failure, token sums, average latency) plus an overall summary --
 * the shape the ai-usage dashboard route serves directly.
 */
export function getAiUsageRollup() {
  const byProvider = {};
  const byTask = {};
  let totalRequests = 0;
  let totalSuccess = 0;
  let totalFailure = 0;
  let totalTokens = 0;
  let cacheHits = 0;

  for (const e of entries) {
    totalRequests += 1;
    if (e.status === "success") totalSuccess += 1;
    else totalFailure += 1;
    if (e.cacheHit) cacheHits += 1;
    totalTokens += e.totalTokens ?? 0;

    const p = (byProvider[e.provider] ??= { provider: e.provider, requests: 0, success: 0, failure: 0, totalTokens: 0, latencySumMs: 0, latencyCount: 0 });
    p.requests += 1;
    if (e.status === "success") p.success += 1;
    else p.failure += 1;
    p.totalTokens += e.totalTokens ?? 0;
    if (typeof e.latencyMs === "number") {
      p.latencySumMs += e.latencyMs;
      p.latencyCount += 1;
    }

    if (e.task) {
      const t = (byTask[e.task] ??= { task: e.task, requests: 0, success: 0, failure: 0, totalTokens: 0 });
      t.requests += 1;
      if (e.status === "success") t.success += 1;
      else t.failure += 1;
      t.totalTokens += e.totalTokens ?? 0;
    }
  }

  const finalizeProvider = (p) => ({ ...p, avgLatencyMs: p.latencyCount > 0 ? Math.round(p.latencySumMs / p.latencyCount) : null, latencySumMs: undefined, latencyCount: undefined });

  return {
    totalRequests,
    totalSuccess,
    totalFailure,
    totalTokens,
    cacheHits,
    byProvider: Object.values(byProvider).map(finalizeProvider),
    byTask: Object.values(byTask),
  };
}
