// Drains the news pool through generateThreatSummary() -- scoped to major
// vendor/security-firm threat research and CISA advisories only (see
// MAJOR_VENDOR_SOURCES in server/connectors/newsFeeds.js), matching this
// feature's actual ask: SOC-grade reports on vendor/CERT-grade advisories,
// not the full ~200-source journalism/aggregator firehose. The full
// enterprise-report schema (25+ sections, several with per-platform hunting-
// query arrays) is far heavier to generate than the 5-category combined
// extraction (server/combinedExtractionJob.js), so this runs one article at
// a time on a slow cadence -- generating for the wrong scope or too
// aggressively would repeat the exact "recomputing something expensive too
// often" mistake already found and fixed in this app (see the news-tagging
// cache fix in server/routes/dashboard.js).
import * as cache from "./cache.js";
import { MAJOR_VENDOR_SOURCES } from "./connectors/newsFeeds.js";
import { tagNewsItems } from "./newsCorrelation.js";
import { generateThreatSummary } from "./aiThreatSummary.js";
import { isArticleProcessed, markArticleProcessed, addReport } from "./aiThreatSummaryStore.js";
import { queryCves } from "./connectors/nvd.js";
import { OllamaUnavailableError } from "./rag/ollamaClient.js";
import { log } from "./lib/log.js";

// Tuned up again to work through the ~400-article Critical/High/Medium
// backlog faster (a separate attempt to also switch to a smaller/faster
// model just for this job was reverted -- see server/rag/config.js -- it
// caused Ollama to thrash swapping between two different loaded models on
// this machine's tight free memory, net slower and less reliable than
// before). Still safe against the overlapping-cycle risk seen elsewhere in
// this app (GitHub Intel enrichment backfill): loop() is self-rescheduling
// and always awaits the full batch before the CYCLE_INTERVAL_MS gap starts,
// so a larger batch just makes one cycle take longer -- it never causes two
// cycles to run concurrently. Each report still lands in the store
// (addReport) as soon as it individually finishes, not only once the whole
// batch completes, so raising BATCH_SIZE shortens time-to-first-report
// within a cycle too.
const BATCH_SIZE = 5;
const CYCLE_INTERVAL_MS = 2 * 60 * 1000; // 2 min

// Per this feature's own spec: only Critical/High/Medium reports for now --
// Low-severity coverage is deliberately deferred, not dropped. Matched
// articles are simply never marked processed while this filter is active,
// so they're picked up automatically the day this list is widened, with no
// backlog-replay step needed.
const ELIGIBLE_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM"]);
const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };

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
  const candidates = newsItems.filter((item) => isEligibleSource(item.source) && !isArticleProcessed(item.link));
  if (candidates.length === 0) return;

  const attackData = cache.getEntry("attack").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries;
  const epssScores = cache.getEntry("epss").data;
  const detectionRuleIndex = cache.getEntry("detection-rules").data?.index ?? [];

  // Severity has to be computed for every not-yet-processed candidate BEFORE
  // slicing to BATCH_SIZE -- otherwise a run of Low-severity articles sitting
  // earlier in the news pool could starve the batch every cycle even while
  // Critical/High/Medium articles are waiting right behind them.
  const tagged = tagNewsItems(candidates, {
    actorNames: (attackData?.groups ?? []).flatMap((g) => [g.name, ...(g.aliases ?? [])]),
    malwareNames: (attackData?.software ?? []).flatMap((s) => [s.name, ...(s.aliases ?? [])]),
    kevIds: new Set((kevEntries ?? []).map((e) => e.cveId)),
    epssScores: epssScores ?? {},
  });

  // tagNewsItems() returns lowercase severity strings ("critical"/"high"/...)
  // -- a convention specific to news tagging, distinct from this app's
  // shared uppercase Severity type ("CRITICAL"/"HIGH"/...) that
  // SeverityBadge and everything else here expects. Confirmed live in an
  // earlier version of this job that leaving it lowercase silently broke
  // both the severity badge's color and the critical-count in the tab
  // header -- normalized once, right here, rather than at every consumer.
  //
  // Confirmed live this app currently has a backlog of ~400+ unprocessed
  // Critical/High/Medium articles across ~200 news sources -- at a few
  // reports per cycle, a genuinely Critical, actively-exploited-CVE article
  // could otherwise sit unprocessed behind hundreds of Medium ones purely
  // because of where it happened to land in the raw news-cache array (no
  // severity or recency ordering existed here before). Sorting Critical
  // first, then newest-first within each tier, means the highest-value
  // articles always get to the front of the queue rather than being left to
  // chance -- it doesn't shrink the backlog, but it fixes *which* articles
  // get covered first.
  const eligible = tagged
    .map((item) => ({ ...item, severity: item.severity.toUpperCase() }))
    .filter((item) => ELIGIBLE_SEVERITIES.has(item.severity))
    .sort((a, b) => {
      const rankDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      if (rankDiff !== 0) return rankDiff;
      return new Date(b.publishedDate) - new Date(a.publishedDate);
    });
  const batch = eligible.slice(0, BATCH_SIZE);
  if (batch.length === 0) return;

  for (const item of batch) {
    try {
      const cveEnrichment = await enrichCveIds(item.tags.cveIds, kevEntries, epssScores);
      const report = await generateThreatSummary(item, {
        cveIds: item.tags.cveIds,
        severity: item.severity,
        cveEnrichment,
        attackTechniques: attackData?.techniques ?? [],
        detectionRuleIndex,
      });
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
