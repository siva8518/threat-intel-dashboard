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

/**
 * Every CVE ID already covered by an existing report -- used by
 * aiThreatSummaryJob.js to skip generating a second full report for the same
 * vulnerability just because a different vendor/outlet also wrote about it
 * (confirmed live: The Cyber Express and Horizon3.ai both produced full
 * separate articles on CVE-2026-20316 within hours of each other). Recomputed
 * on demand from `reports` rather than tracked as a separate persisted set --
 * report count is small (bounded by MAX_REPORTS) so this scan is cheap, and
 * it can never drift out of sync with what's actually in the store.
 */
export function getCoveredCveIds() {
  const ids = new Set();
  for (const report of state.reports) {
    for (const cve of report.cves ?? []) ids.add(cve.id);
  }
  return ids;
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
