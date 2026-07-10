// Disk-backed persistence for discovered/enriched GitHub repos. Unlike every
// other source in this app (in-memory only, cheap to rebuild every restart --
// see server/cache.js), this dataset is expensive to rebuild: GitHub's free
// Search API is 10-30 req/min, so losing it on every dev-server restart would
// mean slowly re-earning it back. A flat JSON file is enough for the
// realistic scale here (hundreds to low-thousands of repos) -- swap for a
// real database only if that stops being true.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "repos.json");

function emptyStore() {
  return { repos: {} };
}

/** Reads the persisted store from disk, or returns an empty one if it doesn't exist yet (first run) or is corrupt. */
export function loadStore() {
  try {
    const raw = fs.readFileSync(STORE_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed.repos === "object" ? parsed : emptyStore();
  } catch {
    return emptyStore(); // missing file (first run) or corrupt JSON -- either way, start fresh rather than crash the connector
  }
}

export function saveStore(store) {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(store), "utf-8");
}

/**
 * Merges freshly-discovered metadata into an existing repo record (if any)
 * without clobbering enrichment data already computed for it. `discoveredAt`
 * is set once, the first time this app ever sees the repo, and preserved on
 * every later re-discovery -- used by server/todaySecurityEvents.js's
 * "GitHub Exploits" count, which needs "when we first found this repo", not
 * GitHub's own repo-creation date (often much older than when it actually
 * showed up in our search results) or `lastEnrichedAt` (updated on every
 * re-enrichment pass, not just the first).
 */
export function upsertRepoMetadata(store, metadata) {
  const existing = store.repos[metadata.fullName];
  store.repos[metadata.fullName] = { ...existing, ...metadata, discoveredAt: existing?.discoveredAt ?? new Date().toISOString() };
  return store.repos[metadata.fullName];
}

export function listRepos(store) {
  return Object.values(store.repos);
}

/** Repos that have never been enriched, or whose enrichment is older than maxAgeMs. */
export function reposNeedingEnrichment(store, maxAgeMs, limit) {
  const now = Date.now();
  return listRepos(store)
    .filter((r) => !r.lastEnrichedAt || now - new Date(r.lastEnrichedAt).getTime() > maxAgeMs)
    .sort((a, b) => new Date(a.lastEnrichedAt ?? 0) - new Date(b.lastEnrichedAt ?? 0)) // never-enriched (epoch 0) and stalest first
    .slice(0, limit);
}
