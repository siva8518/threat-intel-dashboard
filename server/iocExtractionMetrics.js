// Per-source, per-cycle extraction yield counters -- the diagnostic this
// pipeline never had before: no code anywhere in this app previously
// tracked how many IOCs a given source actually produced, only whether it
// synced successfully (server/sourceHealth.js). A vendor that syncs cleanly
// but yields zero validated IOCs across many processed articles is a likely
// parser/extraction gap, not proof the source has nothing to report -- this
// store is what lets that distinction actually be seen instead of assumed.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "ioc-extraction-metrics.json");

function emptyTotals() {
  return { articlesProcessed: 0, candidates: 0, validated: 0, duplicates: 0, failures: 0 };
}

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return {
      cumulative: { ...emptyTotals(), ...parsed.cumulative },
      bySource: parsed.bySource && typeof parsed.bySource === "object" ? parsed.bySource : {},
      lastCycleAt: parsed.lastCycleAt ?? null,
    };
  } catch {
    return { cumulative: emptyTotals(), bySource: {}, lastCycleAt: null };
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(state), "utf-8");
}

/**
 * @param {{articlesProcessed:number, candidates:number, validated:number, duplicates:number, failures:number, bySource: Map<string, {articlesProcessed:number, candidates:number, validated:number}>}} cycleResult
 */
export function recordCycle({ articlesProcessed, candidates, validated, duplicates, failures, bySource }) {
  state.cumulative.articlesProcessed += articlesProcessed;
  state.cumulative.candidates += candidates;
  state.cumulative.validated += validated;
  state.cumulative.duplicates += duplicates;
  state.cumulative.failures += failures;
  state.lastCycleAt = new Date().toISOString();

  for (const [source, counts] of bySource.entries()) {
    const existing = state.bySource[source] ?? emptyTotals();
    existing.articlesProcessed += counts.articlesProcessed;
    existing.candidates += counts.candidates;
    existing.validated += counts.validated;
    state.bySource[source] = existing;
  }

  persist();
}

/**
 * Per-source coverage table -- flags a source as a likely parser/extraction
 * failure when it has processed real articles but validated zero IOCs from
 * any of them, rather than the platform silently reading that as "this
 * source just has no IOCs to report."
 */
export function getCoverageReport() {
  const rows = Object.entries(state.bySource)
    .map(([source, counts]) => ({
      source,
      articlesProcessed: counts.articlesProcessed,
      candidates: counts.candidates,
      validated: counts.validated,
      // "Success" here means the extractor found ANY candidate at all in
      // this source's articles -- a source that keeps re-confirming
      // already-known indicators (candidates > 0, validated low) is still
      // extracting successfully, just not producing many NEW IOCs; that's a
      // separate, non-alarming signal from a source where extraction found
      // literally nothing despite real articles being processed.
      successRate: counts.articlesProcessed > 0 ? Math.round((counts.candidates > 0 ? 1 : 0) * 100) : null,
      newIocRate: counts.candidates > 0 ? Math.round((counts.validated / counts.candidates) * 100) : null,
      likelyParserFailure: counts.articlesProcessed > 0 && counts.candidates === 0,
    }))
    .sort((a, b) => b.articlesProcessed - a.articlesProcessed);

  return { cumulative: state.cumulative, lastCycleAt: state.lastCycleAt, bySource: rows };
}
