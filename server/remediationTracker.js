// User-set remediation status per CVE ("Patched" / "Mitigated" / "Risk
// Accepted") -- the one piece of this feature this app has no other way to
// know, since it depends on an org's own patch rollout, not anything a feed
// reports. Deliberately just a status + note, no ticketing integration,
// same "lightweight queue with state" scope as server/watchlist.js. Every
// other field the Remediation Tracker route shows (CVSS/KEV/EPSS/patch
// guidance) is recomputed live from data this app already syncs -- this
// store only ever holds the one thing a human decided.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "remediation-tracker.json");

export const REMEDIATION_STATUSES = ["pending", "patched", "mitigated", "risk_accepted"];

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

/** Every CVE this app has ever recorded a status for, keyed by uppercase CVE ID. Untracked CVEs simply aren't in here -- the route layer defaults those to "pending" rather than this store needing an entry for every CVE NVD has ever published. */
export function getAllStatuses() {
  return state.records;
}

export function getStatus(cveId) {
  return state.records[cveId.toUpperCase()] ?? null;
}

export function setStatus(cveId, status, note) {
  if (!REMEDIATION_STATUSES.includes(status)) throw new Error(`Invalid status "${status}"`);
  const id = cveId.toUpperCase();
  const record = { status, note: note?.trim() || null, updatedAt: new Date().toISOString() };
  state.records[id] = record;
  persist();
  return record;
}

/** Reverts a CVE back to untracked ("pending" with no note/history) -- distinct from setStatus(id, "pending"), which would still leave a note/timestamp behind. */
export function clearStatus(cveId) {
  const id = cveId.toUpperCase();
  const existed = id in state.records;
  delete state.records[id];
  if (existed) persist();
  return existed;
}
