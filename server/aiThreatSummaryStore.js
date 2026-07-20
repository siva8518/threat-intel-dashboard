// Persisted store for AI-generated SOC threat reports -- one record per
// summarized article, same "load once, persist to disk, never silently
// dropped" pattern as server/malwareIntelligence.js and
// server/threatActorIntelligence.js. Kept as its own tiny module (not folded
// into aiThreatSummaryJob.js) so the route layer can read it without pulling
// in the Ollama call machinery.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "ai-threat-summaries.json");
const MAX_REPORTS = 300; // bounded so this file (and the tab's list) doesn't grow unbounded over months of runtime

// Report generation moved from a continuous every-2-minutes drip to one
// batch a day (see aiThreatSummaryJob.js) specifically to cut how often this
// app hits the local Ollama model -- keeping reports around indefinitely
// (up to MAX_REPORTS) no longer matches that "today's reports" cadence, so
// this store now also rotates anything older than a day out on its own,
// same "clear it, don't just cap the count" ask that motivated the cadence
// change in the first place.
const MAX_REPORT_AGE_MS = 24 * 60 * 60 * 1000;

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return {
      reports: Array.isArray(parsed.reports) ? parsed.reports : [],
      processedArticleIds: Array.isArray(parsed.processedArticleIds) ? parsed.processedArticleIds : [],
      lastCycleAt: typeof parsed.lastCycleAt === "string" ? parsed.lastCycleAt : null,
    };
  } catch {
    return { reports: [], processedArticleIds: [], lastCycleAt: null }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  const trimmed = {
    reports: state.reports.slice(0, MAX_REPORTS),
    processedArticleIds: state.processedArticleIds.slice(-5000),
    lastCycleAt: state.lastCycleAt,
  };
  fs.writeFileSync(STORE_PATH, JSON.stringify(trimmed), "utf-8");
}

/**
 * Drops any report whose generatedAt is more than 24h old. Called once at
 * the start of every daily cycle (aiThreatSummaryJob.js#runCycle), not on
 * every read -- pruning on every GET would empty the tab mid-day the moment
 * yesterday's reports crossed the 24h line, well before today's fresh batch
 * finishes generating. Doing it once, right before that day's batch starts,
 * keeps the "old reports gone, new ones arriving" swap as one clean step
 * instead of a slow bleed-out with nothing to replace it.
 */
export function pruneExpiredReports() {
  const cutoff = Date.now() - MAX_REPORT_AGE_MS;
  const before = state.reports.length;
  state.reports = state.reports.filter((r) => new Date(r.generatedAt).getTime() >= cutoff);
  if (state.reports.length !== before) persist();
}

export function isArticleProcessed(articleId) {
  return state.processedArticleIds.includes(articleId);
}

export function addReport(report) {
  state.reports.unshift(report); // newest first
  state.reports = state.reports.slice(0, MAX_REPORTS);
  if (!state.processedArticleIds.includes(report.articleLink)) {
    state.processedArticleIds.push(report.articleLink);
  }
  persist();
}

/** Marks an article as attempted without adding a report -- e.g. the model returned unusable output. Prevents retrying the same bad article forever. */
export function markArticleProcessed(articleId) {
  if (!state.processedArticleIds.includes(articleId)) {
    state.processedArticleIds.push(articleId);
    persist();
  }
}

export function getAllReports() {
  return state.reports;
}

export function getReportById(id) {
  return state.reports.find((r) => r.id === id) ?? null;
}

/** Wall-clock timestamp of the last time a daily cycle actually ran (not just checked) -- persisted so a backend restart mid-day doesn't reset the 24h clock and re-trigger Ollama load early. See aiThreatSummaryJob.js#loop. */
export function getLastCycleAt() {
  return state.lastCycleAt;
}

export function setLastCycleAt(iso) {
  state.lastCycleAt = iso;
  persist();
}
