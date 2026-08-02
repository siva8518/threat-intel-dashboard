// Drains the news pool through generateThreatSummary() -- the full combined
// ~180-source pool (server/connectors/newsFeeds.js), the same one Daily
// Summary's "Top News" reads from (see BreakingNewsStrip.tsx), not just
// major-vendor/CISA sources. Previously restricted to MAJOR_VENDOR_SOURCES +
// CISA only; widened because that restriction meant an article surfaced in
// Daily Summary from any other source (BleepingComputer, The Hacker News,
// Krebs, any national CERT, etc.) could never get an AI report at all, not
// just delayed -- a permanent gap between what the dashboard flagged as
// breaking and what AI Summarization actually covered. isMajorVendorOrCisa()
// below is kept as a secondary sort tie-break (see buildBatch), not a filter,
// so vendor/CERT-grade advisories still get first crack at each cycle's
// limited slots -- widening eligibility doesn't mean giving up on quality
// prioritization, just removing the hard exclusion.
//
// Also drains one non-news platform source through the SAME pipeline --
// ransomware victim disclosures (ransomwareCandidates()) -- so "AI
// Summarization covers everything this platform tracks" doesn't stop at RSS
// news. It has no real article prose, so it's turned into a genuine (never
// fabricated) title/summary built only from that record's own real fields,
// then run through generateThreatSummary() unchanged -- the existing "say
// Not Reported rather than guess" grounding discipline naturally produces a
// correspondingly thin report for these rather than needing a second report
// schema.
//
// GitHub-discovered exploit repos (githubRepoCandidates(), previously also
// drained here) were removed from the candidate pool: confirmed live these
// "New GitHub repository: ..." reports had come to dominate the stored
// report list, crowding out real vendor/CISA/NVD-tied news coverage, which
// is what this feature is actually for. GitHub Intel still tracks and
// enriches these repos on its own dedicated tab -- this job just no longer
// generates a full AI Summarization report for each one.
//
// The full enterprise-report schema (25+ sections, several with
// per-platform hunting-query arrays) is far heavier to generate than the
// 5-category combined extraction (server/combinedExtractionJob.js), so this
// runs one article at a time on a slow cadence -- generating too
// aggressively would repeat the exact "recomputing something expensive too
// often" mistake already found and fixed in this app (see the news-tagging
// cache fix in server/routes/dashboard.js). Also scoped to
// RECENCY_WINDOW_MS below -- this used to strictly drain an ever-growing
// historical backlog by severity, which on a slow CPU-only local model
// meant it was always working through old ground instead of keeping
// current. Restricting to freshly-published/discovered candidates means the
// job's job is now "keep up with today," a much smaller and steadier
// workload than "eventually finish months of backlog."
import * as cache from "./cache.js";
import { MAJOR_VENDOR_SOURCES } from "./connectors/newsFeeds.js";
import { getTaggedNewsItems } from "./newsCorrelation.js";
import { threatFeedIocs } from "./threatFeed.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "./ransomwareCampaigns.js";
import { getAllEntities as getMalwareIntelligenceEntities } from "./malwareIntelligence.js";
import { getAllEntities as getThreatActorIntelligenceEntities } from "./threatActorIntelligence.js";
import { generateThreatSummary } from "./aiThreatSummary.js";
import { isArticleProcessed, markArticleProcessed, addReport, getLastCycleAt, setLastCycleAt } from "./aiThreatSummaryStore.js";
import { queryCves } from "./connectors/nvd.js";
import { AllProvidersFailedError } from "./ai/aiRouter.js";
import { log } from "./lib/log.js";

// A separate attempt to also switch to a smaller/faster model just for this
// job was reverted -- see server/rag/config.js -- it caused Ollama to
// thrash swapping between two different loaded models on this machine's
// tight free memory, net slower and less reliable than before. Safe against
// the overlapping-cycle risk seen elsewhere in this app (GitHub Intel
// enrichment backfill): loop() is self-rescheduling and always awaits the
// full batch before the next cycle is due, so a larger batch just makes one
// cycle take longer -- it never causes two cycles to run concurrently. Each
// report still lands in the store (addReport) as soon as it individually
// finishes, not only once the whole batch completes, so raising BATCH_SIZE
// shortens time-to-first-report within a cycle too.
//
// Moved from a continuous every-2-minutes drip to one batch a day -- this
// was the actual, most direct lever for cutting how often this app hits the
// local Ollama model, distinct from (and on top of) the timeout/watchdog/
// queue mitigations already in place for the deadlock itself. BATCH_SIZE
// raised from 5 to 20 to match: at once-a-day, 5 would leave most of a
// day's Critical/High volume never covered before it aged out of
// RECENCY_WINDOW_MS below, defeating the "new reports flowing in" goal this
// cadence change is for.
//
// The store's own 24h report-retention window was removed (see
// aiThreatSummaryStore.js) -- with Groq's free tier frequently unable to
// complete a full batch before rate-limiting, pruning "yesterday's" reports
// on a fixed clock could empty the tab for a long stretch with nothing yet
// generated to replace them. Reports now simply accumulate up to
// MAX_REPORTS and age out by count, not by a clock.
const BATCH_SIZE = 20;
const CYCLE_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24h -- the real generation cadence, persisted (see below), not just a setTimeout gap
// How often loop() wakes up to check whether CYCLE_INTERVAL_MS has actually
// elapsed since the last real run -- cheap (a Date comparison against a
// persisted timestamp), so this can run far more often than generation
// itself without adding any Ollama load. Needed because this backend gets
// restarted often (Ollama crash recovery, deploys, the scheduled restart
// task) -- without persisting lastCycleAt, every restart would otherwise
// re-arm a fresh 24h setTimeout and could drift into running much more than
// once a day, exactly what this change is meant to prevent.
const CHECK_INTERVAL_MS = 10 * 60 * 1000; // 10 min

// Widened to include Low -- per this feature's own spec, Low was deferred
// (never marked processed while excluded), not dropped, specifically so
// this moment -- flipping the filter -- would surface the whole backlog
// automatically with no separate backfill step. Confirmed live a lot of
// legitimate vendor-source articles were sitting unprocessed simply because
// they tagged Low, not because anything was broken.
const ELIGIBLE_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// Strict Critical>High>Medium>Low ordering (below) picks the single best
// article every cycle, but it has no anti-starvation guard: as long as new
// Critical/High CVE articles keep arriving from the news pool -- which they
// do, continuously -- Medium/Low never get reached at all, not just
// delayed. Confirmed live: a 944-article backlog was 823 Low (mostly
// malware-family/threat-actor pieces that never picked up a CVE mention --
// computeSeverity in newsCorrelation.js only reaches Medium if the title
// matches an already-curated ATT&CK/ransomware-tracker name, so a newer or
// lesser-known family name defaults to Low), and after days of this
// ordering zero Low articles had ever been processed. Reserving a couple of
// the batch's slots specifically for the oldest Medium/Low article
// guarantees both tiers make steady forward progress every cycle,
// regardless of how deep the Critical/High backlog runs.
const RESERVED_SLOTS = { MEDIUM: 1, LOW: 1 };

// Tie-break only now, not a filter (see the top-of-file comment) -- still
// used to prefer vendor/CERT-grade advisories within the same severity tier
// when building each cycle's batch below.
function isMajorVendorOrCisa(source) {
  return MAJOR_VENDOR_SOURCES.has(source) || source.startsWith("CISA");
}

// Scoped to freshly-published advisories only -- previously this drained an
// ever-growing historical backlog (~944 articles at one point, some weeks
// old) strictly by severity, which meant a slow CPU-only local model was
// always working through old ground instead of keeping up with what
// vendors/CISA published today. An article older than this window is never
// marked processed (same "deferred, not dropped" precedent as the Low-
// severity widening above) -- it simply ages out of eligibility on its own
// as `now` moves past its publish date, so nothing needs a destructive bulk
// skip and a later change to this constant costs nothing. 48h (not 24h)
// gives feeds a bit of slack for sync lag/timezone skew without pulling in
// genuinely old ground.
const RECENCY_WINDOW_MS = 48 * 60 * 60 * 1000;

function isRecent(publishedDate) {
  return Date.now() - new Date(publishedDate).getTime() <= RECENCY_WINDOW_MS;
}

/**
 * Fills BATCH_SIZE slots from `eligible` (already sorted Critical>High>
 * Medium>Low, newest-first within a tier): first claims RESERVED_SLOTS'
 * newest pick from each tier it names, then fills whatever's left in strict
 * priority order, skipping anything already claimed. With BATCH_SIZE=5 and
 * RESERVED_SLOTS={MEDIUM:1,LOW:1}, that's usually 3 slots of pure priority
 * (which Critical/High will dominate whenever they're present) plus 1
 * guaranteed Medium and 1 guaranteed Low every cycle.
 */
function buildBatch(eligible) {
  const batch = [];
  const claimed = new Set();
  for (const [severity, count] of Object.entries(RESERVED_SLOTS)) {
    for (const item of eligible.filter((i) => i.severity === severity).slice(0, count)) {
      batch.push(item);
      claimed.add(item.link);
    }
  }
  for (const item of eligible) {
    if (batch.length >= BATCH_SIZE) break;
    if (claimed.has(item.link)) continue;
    batch.push(item);
    claimed.add(item.link);
  }
  return batch.slice(0, BATCH_SIZE);
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

/**
 * Distinct from "genuinely zero eligible candidates today" -- thrown when
 * the news cache hasn't populated yet at all (cache.getEntry returns no
 * `.data`), which only happens in the ~30-60s window right after a cold
 * boot before the news connector's first sync completes. Confirmed live:
 * this job's own 30s startup delay is shorter than that window, so its
 * very first check on a fresh boot could see an empty cache, call it "no
 * candidates," and -- under the daily cadence -- lock the schedule for 24h
 * having never actually looked at real data. safeCycle() below treats this
 * the same as an Ollama outage: don't advance lastCycleAt, just retry on
 * the next CHECK_INTERVAL_MS tick once the cache is actually warm.
 */
class NewsCacheNotReadyError extends Error {}

// Thrown instead of a plain early return so a day with genuinely nothing new
// to summarize doesn't get treated the same as a day that actually generated
// reports. Confirmed live: with a plain `return`, safeCycle() saw this as a
// full success and called setLastCycleAt(), locking the schedule for a full
// 24h even though zero reports were produced -- combined with an extended
// Groq outage eating into the same window and the store's own 24h report
// rotation pruning whatever was already there, the tab went completely
// empty for the better part of a day with no way to recover early even
// after Groq came back and new articles arrived. Checking for candidates is
// just a cache filter, no LLM call -- so retrying this every
// CHECK_INTERVAL_MS instead of waiting out the full cycle costs nothing
// against Groq's quota; lastCycleAt only ever advances once real work
// (a non-empty batch) has actually been attempted.
class NoEligibleCandidatesError extends Error {}

function slugify(text) {
  return (text ?? "").toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

// Ransomware victim disclosures and GitHub-discovered exploit repos have no
// narrative article text of their own -- unlike every other candidate here,
// they're structured records (a group/victim/date, or a repo's own
// metadata), not prose a report can extract technical detail from. Rather
// than build a second, thinner report schema for them, this synthesizes a
// real (never fabricated -- every field below comes straight from the
// record itself) title/summary from their own data and feeds them through
// the exact same generateThreatSummary() pipeline as a news article. The
// existing "say Not Reported rather than guess" grounding discipline
// naturally produces a correspondingly thin report for these -- most
// narrative sections legitimately empty, but severity/CVE/reference fields
// still real -- without any schema or prompt change.
function ransomwareCandidates(campaigns) {
  return (campaigns ?? [])
    .filter((c) => c.group && c.victim && c.discoveredDate)
    .map((c) => ({
      title: `${c.group} lists new ransomware victim: ${c.victim}`,
      summary:
        `Ransomware group "${c.group}" added "${c.victim}" to its leak site` +
        (c.sector && c.sector !== "Unknown" ? `, sector: ${c.sector}` : "") +
        (c.country && c.country !== "Unknown" ? `, country: ${c.country}` : "") +
        `. Discovered ${c.discoveredDate}.`,
      // A real per-victim/group leak-site URL when known (fetchArticleText()
      // in aiThreatSummary.js will genuinely try to fetch it, same as any
      // news link) -- a stable synthetic identifier otherwise, purely for
      // isArticleProcessed() dedup, never shown as if it were a real source.
      link: c.sourceUrl || `ransomware-victim://${slugify(c.group)}/${slugify(c.victim)}`,
      source: `${c.group} (Ransomware Leak Site)`,
      publishedDate: c.discoveredDate,
    }));
}

async function runCycle() {
  if (!cache.getEntry("news").data) throw new NewsCacheNotReadyError("News cache has not synced yet");

  const newsItems = cache.getEntry("news").data?.items ?? [];
  const allCandidateSources = [...newsItems, ...ransomwareCandidates(getRansomwareCampaigns())];
  const candidates = allCandidateSources.filter((item) => isRecent(item.publishedDate) && !isArticleProcessed(item.link));
  if (candidates.length === 0) throw new NoEligibleCandidatesError("No eligible candidates in this check");

  const attackData = cache.getEntry("attack").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries;
  const epssScores = cache.getEntry("epss").data;
  const detectionRuleIndex = cache.getEntry("detection-rules").data?.index ?? [];

  // Severity has to be computed for every not-yet-processed candidate BEFORE
  // slicing to BATCH_SIZE -- otherwise a run of Low-severity articles sitting
  // earlier in the news pool could starve the batch every cycle even while
  // Critical/High/Medium articles are waiting right behind them.
  //
  // Uses the same shared getTaggedNewsItems() as Daily Summary/Emerging
  // Threats/Security News (server/routes/dashboard.js's getTaggedNewsCached())
  // instead of a narrower inline ATT&CK-only tagNewsItems() call this job
  // used to make on its own -- confirmed live those two tagging passes had
  // drifted apart, so an article whose only actor/malware signal came from
  // Malware/Threat Actor Intelligence (not ATT&CK's own catalog) computed a
  // lower severity here than it showed elsewhere in the app, silently
  // de-prioritizing it in this job's Critical-first batch ordering.
  const tagged = getTaggedNewsItems({
    newsItems: candidates,
    attackData,
    ransomwareCampaigns: getRansomwareCampaigns(),
    threatFeedIocs: threatFeedIocs(),
    kevEntries,
    epssScores,
    malwareEntities: getMalwareIntelligenceEntities(),
    threatActorEntities: getThreatActorIntelligenceEntities(),
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
      // Vendor/CERT-grade sources still go first within the same severity
      // tier -- widening eligibility to the full source pool (see top-of-
      // file comment) shouldn't mean giving up this quality priority.
      const vendorDiff = Number(isMajorVendorOrCisa(b.source)) - Number(isMajorVendorOrCisa(a.source));
      if (vendorDiff !== 0) return vendorDiff;
      // An article that already resolves to a real NVD/CVE record gets
      // priority within its tier too -- this is exactly the "Vendor
      // Confirmed Intelligence" content the report's IOC/CVE sections are
      // built to ground against, so it produces a fuller report than an
      // article with no CVE tie at all.
      const cveDiff = Number((b.tags?.cveIds?.length ?? 0) > 0) - Number((a.tags?.cveIds?.length ?? 0) > 0);
      if (cveDiff !== 0) return cveDiff;
      return new Date(b.publishedDate) - new Date(a.publishedDate);
    });
  const batch = buildBatch(eligible);
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
      if (error instanceof AllProvidersFailedError) throw error; // stop the cycle -- every AI provider being down/rate-limited affects every remaining article the same way
      log.error("ai-threat-summary", `failed to summarize "${item.title.slice(0, 60)}...": ${error.message}`);
      markArticleProcessed(item.link);
    }
  }

  log.info("ai-threat-summary", `processed ${batch.length} article(s) from ${[...new Set(batch.map((b) => b.source))].join(", ")}`);
}

let hasWarnedUnavailable = false;

/**
 * Returns whether today's cycle should count as "done" for lastCycleAt
 * purposes. Every configured AI provider being unavailable (down, or
 * rate-limited/quota-exhausted -- server/ai/aiRouter.js already tried each
 * one, with retries, before giving up) does NOT count -- if the daily cycle
 * lands during an outage, we want the next CHECK_INTERVAL_MS tick to retry
 * (and keep retrying) until at least one provider recovers, not silently
 * skip an entire day's reports waiting for the next 24h boundary. Zero
 * eligible candidates also does NOT count, same reasoning -- see
 * NoEligibleCandidatesError above. Any other failure (a bad article, an
 * NVD hiccup) still counts as this day's attempt -- those already log
 * per-article inside runCycle() and don't warrant a retry-loop every 10
 * minutes.
 */
async function safeCycle() {
  try {
    await runCycle();
    hasWarnedUnavailable = false;
    return true;
  } catch (error) {
    if (error instanceof AllProvidersFailedError) {
      if (!hasWarnedUnavailable) {
        log.warn("ai-threat-summary", `${error.message} -- AI Summarization will report itself unavailable until at least one provider is reachable again.`);
        hasWarnedUnavailable = true;
      }
      return false;
    }
    if (error instanceof NewsCacheNotReadyError || error instanceof NoEligibleCandidatesError) {
      // Deliberately no log line for either -- both fire routinely (cold
      // boot / a genuinely quiet news cycle) and would just be noise; not a
      // fault, resolved on its own the moment real data/candidates show up.
      return false;
    }
    log.error("ai-threat-summary", `cycle failed: ${error.message}`);
    return true;
  }
}

/**
 * Wakes up every CHECK_INTERVAL_MS (cheap -- just a Date comparison) and
 * only actually runs a cycle once CYCLE_INTERVAL_MS has elapsed since the
 * last one that completed, per the persisted lastCycleAt (see
 * aiThreatSummaryStore.js). This is what makes the daily cadence survive
 * backend restarts -- a plain setTimeout(loop, 24h) would otherwise reset
 * to a fresh 24h wait on every restart, which given how often this backend
 * gets restarted (Ollama recovery, deploys, the scheduled restart task)
 * could mean it never actually fires, or fires far more than once a day.
 */
async function loop() {
  const last = getLastCycleAt();
  const due = !last || Date.now() - new Date(last).getTime() >= CYCLE_INTERVAL_MS;
  if (due) {
    const completed = await safeCycle();
    if (completed) setLastCycleAt(new Date().toISOString());
  }
  setTimeout(loop, CHECK_INTERVAL_MS);
}

export function startAiThreatSummaryJob() {
  setTimeout(loop, 30_000); // after the combined-extraction job's own warm-up, so the news/attack/kev/epss caches are warm
}
