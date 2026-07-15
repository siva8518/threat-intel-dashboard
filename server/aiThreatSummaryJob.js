// Drains the news pool through generateThreatSummary() -- scoped to major
// vendor/security-firm threat research and CISA advisories only (see
// MAJOR_VENDOR_SOURCES in server/connectors/newsFeeds.js), matching this
// feature's actual ask: SOC-grade reports on vendor/CERT-grade advisories,
// not the full ~200-source journalism/aggregator firehose. A full 20-field
// structured report is far heavier to generate than the 5-category combined
// extraction (server/combinedExtractionJob.js), so this runs a small batch
// on a slower cadence -- generating for the wrong scope or too aggressively
// would repeat the exact "recomputing something expensive too often" mistake
// already found and fixed in this app (see the news-tagging cache fix in
// server/routes/dashboard.js).
import * as cache from "./cache.js";
import { MAJOR_VENDOR_SOURCES } from "./connectors/newsFeeds.js";
import { tagNewsItems } from "./newsCorrelation.js";
import { generateThreatSummary } from "./aiThreatSummary.js";
import { isArticleProcessed, markArticleProcessed, addReport } from "./aiThreatSummaryStore.js";
import { queryCves } from "./connectors/nvd.js";
import { OllamaUnavailableError } from "./rag/ollamaClient.js";
import { log } from "./lib/log.js";

const BATCH_SIZE = 3; // conservative -- each report is a much larger generation than the 5-category combined extraction
const CYCLE_INTERVAL_MS = 10 * 60 * 1000; // 10 min

function isEligibleSource(source) {
  return MAJOR_VENDOR_SOURCES.has(source) || source.startsWith("CISA");
}

const cveEnrichmentCache = new Map(); // process-wide, same pattern as githubIntel/enrich.js's cveDetailCache -- a CVE looked up once doesn't need a second live NVD call this run

async function enrichCveIds(cveIds, kevEntries, epssScores) {
  const kevIds = new Set((kevEntries ?? []).map((e) => e.cveId));
  const epss = epssScores ?? {};
  const enrichment = {};

  for (const id of cveIds) {
    if (cveEnrichmentCache.has(id)) {
      enrichment[id] = cveEnrichmentCache.get(id);
      continue;
    }
    let record = { id, severity: "UNKNOWN", cvssScore: null, sourceUrl: `https://nvd.nist.gov/vuln/detail/${id}` };
    try {
      const result = await queryCves({ cveId: id, resultsPerPage: 1 });
      if (result.records[0]) record = result.records[0];
    } catch {
      // Best-effort -- a single NVD lookup failing shouldn't block the report; the ground-truth CVE ID itself still gets reported.
    }
    const enriched = { ...record, knownExploited: kevIds.has(id), epssScore: epss[id]?.score ?? null };
    cveEnrichmentCache.set(id, enriched);
    enrichment[id] = enriched;
  }

  return enrichment;
}

async function runCycle() {
  const newsItems = cache.getEntry("news").data?.items ?? [];
  const eligible = newsItems.filter((item) => isEligibleSource(item.source) && !isArticleProcessed(item.link));
  const batch = eligible.slice(0, BATCH_SIZE);
  if (batch.length === 0) return;

  const attackData = cache.getEntry("attack").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries;
  const epssScores = cache.getEntry("epss").data;

  const tagged = tagNewsItems(batch, {
    actorNames: (attackData?.groups ?? []).flatMap((g) => [g.name, ...(g.aliases ?? [])]),
    malwareNames: (attackData?.software ?? []).flatMap((s) => [s.name, ...(s.aliases ?? [])]),
    kevIds: new Set((kevEntries ?? []).map((e) => e.cveId)),
    epssScores: epssScores ?? {},
  });

  for (const item of tagged) {
    try {
      const cveEnrichment = await enrichCveIds(item.tags.cveIds, kevEntries, epssScores);
      const report = await generateThreatSummary(item, { cveIds: item.tags.cveIds, severity: item.severity, cveEnrichment });
      if (report) {
        addReport(report);
      } else {
        markArticleProcessed(item.link);
      }
    } catch (error) {
      if (error instanceof OllamaUnavailableError) throw error; // stop the cycle -- Ollama being down affects every remaining article the same way
      log.error("ai-threat-summary", `failed to summarize "${item.title.slice(0, 60)}...": ${error.message}`);
      markArticleProcessed(item.link);
    }
  }

  log.info("ai-threat-summary", `processed ${batch.length} article(s) from ${[...new Set(batch.map((b) => b.source))].join(", ")}`);
}

let hasWarnedUnavailable = false;

async function safeCycle() {
  try {
    await runCycle();
    hasWarnedUnavailable = false;
  } catch (error) {
    if (error instanceof OllamaUnavailableError) {
      if (!hasWarnedUnavailable) {
        log.warn("ai-threat-summary", `${error.message} -- AI Summarization will report itself unavailable until Ollama is running.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("ai-threat-summary", `cycle failed: ${error.message}`);
    }
  }
}

/** Self-rescheduling, same reasoning as server/combinedExtractionJob.js#loop -- a report generation can run long on CPU-only local inference, and this guarantees exactly one cycle in flight at a time. */
async function loop() {
  await safeCycle();
  setTimeout(loop, CYCLE_INTERVAL_MS);
}

export function startAiThreatSummaryJob() {
  setTimeout(loop, 30_000); // after the combined-extraction job's own warm-up, so the news/attack/kev/epss caches are warm
}
