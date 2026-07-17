// User-set status per detection-backlog item ("In Progress" / "Implemented"
// / "Won't Do") -- the same "this app has no other way to know it" scope as
// server/remediationTracker.js, just for Detection Engineering's own backlog
// instead of Vulnerability Management's. Backlog items themselves are
// re-derived from AI Summarization reports on every request (see
// server/detectionBacklog.js), not stored here -- only the human decision
// about each one is.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "detection-backlog-tracker.json");

export const DETECTION_BACKLOG_STATUSES = ["open", "in_progress", "implemented", "wont_do"];

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return { records: parsed && typeof parsed.records === "object" ? parsed.records : {} };
  } catch {
    return { records: {} }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(state), "utf-8");
}

export function getAllStatuses() {
  return state.records;
}

export function setStatus(itemId, status, note) {
  if (!DETECTION_BACKLOG_STATUSES.includes(status)) throw new Error(`Invalid status "${status}"`);
  const record = { status, note: note?.trim() || null, updatedAt: new Date().toISOString() };
  state.records[itemId] = record;
  persist();
  return record;
}

export function clearStatus(itemId) {
  const existed = itemId in state.records;
  delete state.records[itemId];
  if (existed) persist();
  return existed;
}
