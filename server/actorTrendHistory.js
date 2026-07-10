// Rolling daily snapshots of per-actor activity scores, used only to compute
// a real day-over-day trend arrow for server/topThreatActorsToday.js. Same
// pattern as server/malwareTrendHistory.js (kept as a separate file rather
// than a shared generic module -- both are small, stable, single-purpose
// utilities, not worth coupling together).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "actor-trend-history.json");
const MAX_SNAPSHOTS = 14; // only the most recent prior day is ever read; kept a little slack

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
 * Records today's actor-score snapshot once per day (a second call the same
 * day is a no-op) and returns the most recent snapshot from a PRIOR day, if
 * any, to compute a real trend against.
 */
export function recordAndGetPriorActorSnapshot(actorScores) {
  const history = loadHistory();
  const today = todayDate();

  const prior = history.filter((s) => s.date !== today).sort((a, b) => (a.date < b.date ? 1 : -1))[0] ?? null;

  if (!history.some((s) => s.date === today)) {
    const pruned = [...history, { date: today, actors: actorScores }].sort((a, b) => (a.date < b.date ? 1 : -1)).slice(0, MAX_SNAPSHOTS);
    saveHistory(pruned);
  }

  return prior;
}
