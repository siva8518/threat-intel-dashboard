// Rolling daily snapshots of the Executive Threat Summary score + active
// campaign volume -- same rolling-snapshot pattern as
// server/sourceReliabilityHistory.js / server/malwareTrendHistory.js. The
// score itself (server/executiveSummary.js) is always a live recompute with
// no memory of yesterday, so this is the one place that persists a small
// daily window to disk, letting the frontend draw a real trend line instead
// of a single snapshot number.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "threat-score-history.json");
const MAX_SNAPSHOTS = 30; // ~a month of daily history

function todayDate() {
  return new Date().toISOString().slice(0, 10);
}

function loadHistory() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return []; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function saveHistory(history) {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(history), "utf-8");
}

/**
 * Records today's { score, totalActiveCampaigns } snapshot once per day (a
 * second call the same day is a no-op) and returns the full rolling history
 * (oldest first, up to MAX_SNAPSHOTS days) for the trend widgets.
 */
export function recordAndGetScoreHistory(score, totalActiveCampaigns) {
  const history = loadHistory().sort((a, b) => (a.date < b.date ? -1 : 1));
  const today = todayDate();

  if (!history.some((s) => s.date === today)) {
    const pruned = [...history, { date: today, score, totalActiveCampaigns }].slice(-MAX_SNAPSHOTS);
    saveHistory(pruned);
    return pruned;
  }

  return history;
}
