// Rolling daily online/offline snapshots per source, used to compute a real
// Source Reliability Score (% of tracked days a source was online) for the
// Sources tab -- same rolling-snapshot pattern as server/malwareTrendHistory.js
// (kept as its own file rather than a shared generic module: a small,
// stable, single-purpose utility not worth coupling together with others).
//
// Deliberately daily granularity, not per-request: cache.js's health state
// only ever reflects the *current* moment, and this app has no long-running
// persistent process to sample continuously (dev restarts constantly, and
// even in production a free-tier instance can sleep/restart) -- one snapshot
// per calendar day, taken lazily on whichever request happens to hit
// /dashboard/health first that day, is what's actually sustainable here.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "source-reliability-history.json");
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
 * Records today's { sourceKey: online } snapshot once per day (a second
 * call the same day is a no-op) and returns the full rolling history
 * (oldest first, up to MAX_SNAPSHOTS days) for computing reliability scores.
 */
export function recordAndGetSourceHistory(onlineBySourceKey) {
  const history = loadHistory().sort((a, b) => (a.date < b.date ? -1 : 1));
  const today = todayDate();

  if (!history.some((s) => s.date === today)) {
    const pruned = [...history, { date: today, sources: onlineBySourceKey }].slice(-MAX_SNAPSHOTS);
    saveHistory(pruned);
    return pruned;
  }

  return history;
}

/**
 * Reliability score (0-100) for one source key: the percentage of days in
 * the recorded history where it was online, only counting days the source
 * actually existed (so a source added last week isn't punished for not
 * having data from a month ago). Returns `score: null` until there are at
 * least 2 days of history -- a single day's snapshot is just today's status
 * repeated, not a real reliability signal yet.
 */
export function computeReliability(history, sourceKey) {
  let onlineDays = 0;
  let trackedDays = 0;
  for (const snapshot of history) {
    const online = snapshot.sources?.[sourceKey];
    if (online === undefined) continue;
    trackedDays += 1;
    if (online) onlineDays += 1;
  }
  if (trackedDays < 2) return { score: null, trackedDays };
  return { score: Math.round((onlineDays / trackedDays) * 100), trackedDays };
}
