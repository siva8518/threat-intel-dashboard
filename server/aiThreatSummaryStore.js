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
    };
  } catch {
    return { reports: [], processedArticleIds: [] }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  const trimmed = {
    reports: state.reports.slice(0, MAX_REPORTS),
    processedArticleIds: state.processedArticleIds.slice(-5000),
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

export function getReportById(id) {
  return state.reports.find((r) => r.id === id) ?? null;
}
