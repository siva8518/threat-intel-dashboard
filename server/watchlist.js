// User-curated watchlist of client/organization names to continuously
// monitor across every intelligence source this platform already tracks
// (news, malware/actor/campaign/dark-web intelligence, ransomware leak-site
// victim posts) -- see server/watchlistScanner.js for the actual scan.
// Deliberately deterministic word-boundary text matching, not an LLM call:
// this needs to run frequently and cheaply against thousands of already-
// synced records, and "does this exact name appear" doesn't benefit from a
// model's judgment the way open-set entity extraction does.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "watchlist.json");
const MAX_FLASH_REPORTS = 500; // trimmed oldest-first once exceeded, same bounding pattern as every other store's article-list caps

// A keyword added today can instantly match hundreds of already-synced
// backlog articles/entities going back months -- without this window, every
// one of those lands as an "unread" flash report at once, and the banner
// never seems to clear because reading one just reveals the next backlog
// item. Only mentions published within this window are treated as live
// alerts (unread, surfaced in the banner); older matches are still recorded
// -- visible in the Watchlist tab for reference -- but pre-marked read.
const RECENT_WINDOW_MS = 48 * 60 * 60 * 1000;

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    const flashReports = Array.isArray(parsed.flashReports) ? parsed.flashReports : [];

    // One-time migration for reports recorded before the `recent` field
    // existed: without this, everything already sitting in the store from
    // before this fix stays unread forever, defeating the point of it.
    let migrated = false;
    for (const r of flashReports) {
      if (typeof r.recent === "boolean") continue;
      r.recent = Date.now() - new Date(r.foundAt).getTime() <= RECENT_WINDOW_MS;
      if (!r.recent) r.read = true;
      migrated = true;
    }

    const loaded = { keywords: Array.isArray(parsed.keywords) ? parsed.keywords : [], flashReports };
    if (migrated) {
      fs.mkdirSync(STORE_DIR, { recursive: true });
      fs.writeFileSync(STORE_PATH, JSON.stringify(loaded), "utf-8");
    }
    return loaded;
  } catch {
    return { keywords: [], flashReports: [] }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(state), "utf-8");
}

function normalize(s) {
  return (s ?? "").trim().toLowerCase();
}

/**
 * Splits "Grain and Protein Technology (GPT)" into a primary name and a
 * parenthetical alias (matched independently, since coverage almost always
 * uses one or the other, never both together) -- same "aka" pattern already
 * used across every entity store's `aliases` field. A plain name with no
 * parens just becomes the primary with no aliases.
 */
function parseKeyword(raw) {
  const trimmed = raw.trim();
  const match = trimmed.match(/^(.*?)\s*\(([^)]+)\)\s*$/);
  if (match && match[1].trim()) {
    return { primary: match[1].trim(), aliases: [match[2].trim()] };
  }
  return { primary: trimmed, aliases: [] };
}

export function getKeywords() {
  return [...state.keywords].sort((a, b) => a.label.localeCompare(b.label));
}

/** Adds a new watchlist entry; a no-op (returns the existing entry) if the same name (case-insensitive) is already tracked. */
export function addKeyword(raw) {
  const label = raw.trim();
  if (!label) return null;

  const existing = state.keywords.find((k) => normalize(k.label) === normalize(label));
  if (existing) return existing;

  const { primary, aliases } = parseKeyword(label);
  const entry = {
    id: normalize(label).replace(/\s+/g, "-"),
    label,
    primary,
    aliases,
    addedAt: new Date().toISOString(),
  };
  state.keywords.push(entry);
  persist();
  return entry;
}

export function removeKeyword(id) {
  const before = state.keywords.length;
  state.keywords = state.keywords.filter((k) => k.id !== id);
  if (state.keywords.length !== before) persist();
  return state.keywords.length !== before;
}

/** Word-boundary, case-insensitive match -- same guard as server/newsCorrelation.js#matchNames so a short name like "TJU" doesn't match inside an unrelated longer word. */
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function textContainsName(text, name) {
  if (!text || !name) return false;
  const re = new RegExp(`(?:^|[^a-z0-9])${escapeRegExp(name.toLowerCase())}(?:[^a-z0-9]|$)`, "i");
  return re.test(text);
}

/** True if any of `texts` mentions this keyword's primary name or any alias. */
export function keywordMatches(keyword, texts) {
  const names = [keyword.primary, ...keyword.aliases];
  return texts.some((text) => names.some((name) => textContainsName(text, name)));
}

export function getFlashReports() {
  return [...state.flashReports].sort((a, b) => new Date(b.foundAt) - new Date(a.foundAt));
}

export function getUnreadCount() {
  return state.flashReports.filter((r) => !r.read).length;
}

/**
 * Records one keyword<->source match, deduped by (keywordId, sourceType,
 * sourceId) so the same entity/article doesn't re-alert every scan cycle.
 * Returns the new report if this was genuinely new, null if already known.
 */
export function recordMatchIfNew(keyword, { sourceType, sourceId, sourceLabel, title, url, snippet, foundAt }) {
  const dedupeKey = `${keyword.id}|${sourceType}|${sourceId}`;
  if (state.flashReports.some((r) => r.dedupeKey === dedupeKey)) return null;

  const foundAtIso = foundAt ?? new Date().toISOString();
  const recent = Date.now() - new Date(foundAtIso).getTime() <= RECENT_WINDOW_MS;

  const report = {
    id: dedupeKey,
    dedupeKey,
    keywordId: keyword.id,
    keywordLabel: keyword.label,
    sourceType,
    sourceLabel,
    title,
    url: url ?? null,
    snippet: snippet ?? null,
    foundAt: foundAtIso,
    recent,
    read: !recent,
  };
  state.flashReports.unshift(report);
  state.flashReports = state.flashReports.slice(0, MAX_FLASH_REPORTS);
  return report;
}

export function markRead(id) {
  const report = state.flashReports.find((r) => r.id === id);
  if (!report) return false;
  report.read = true;
  persist();
  return true;
}

export function markAllRead() {
  for (const r of state.flashReports) r.read = true;
  persist();
}

export function saveAfterScan() {
  persist();
}
