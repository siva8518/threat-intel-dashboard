// Third background extraction job, decoupled from the other two on purpose.
// server/combinedExtractionJob.js only ever sees title+RSS-summary (1-3
// sentences) and only stores IOCs for articles where its own separate LLM
// pass also independently named a malware family. server/aiThreatSummaryJob.js
// does fetch full article text, but only for ~20 articles/day within a 48h
// window, and stores IOCs at report level, not as canonical per-indicator
// records. Neither gives full-document IOC coverage across this app's whole
// ~166-source pool.
//
// The key fact that makes this job possible at high cadence: regex
// extraction (server/githubIntel/extractor.js#extractEntities) makes ZERO
// calls through server/ai/aiRouter.js. Only the malware/actor/campaign LLM
// pass (combinedExtraction.js) and full report generation
// (aiThreatSummary.js#generateThreatSummary) cost AI provider quota -- this
// job costs none, so it can run far more aggressively than either AI-gated
// job, limited only by politeness to source websites when fetching full
// article HTML (server/lib/articleText.js#fetchArticleText), not by
// provider rate limits.
import * as cache from "./cache.js";
import { extractEntities } from "./githubIntel/extractor.js";
import { fetchArticleText } from "./lib/articleText.js";
import * as iocIntel from "./iocIntelligence.js";
import { extractContextSnippet, enrichIndicatorAsn } from "./iocClassification.js";
import * as malwareIntel from "./malwareIntelligence.js";
import * as actorIntel from "./threatActorIntelligence.js";
import * as campaignIntel from "./campaignIntelligence.js";
import { recordCycle } from "./iocExtractionMetrics.js";
import { log } from "./lib/log.js";

// No AI-quota constraint exists here (see module comment) -- this can run
// far more aggressively than combinedExtractionJob.js's 40/2min. Bounded
// only by fetch politeness to source sites, not provider rate limits.
const MAX_ARTICLES_PER_CYCLE = 60;
const CYCLE_INTERVAL_MS = 60 * 1000;
// An order of magnitude tighter than combinedExtractionJob.js's
// ARTICLE_PACING_MS=4000 -- that pacing exists specifically to stay under
// AI-provider free-tier RPM limits, a constraint that doesn't apply to a
// job that never calls an AI provider. This pacing exists purely to avoid
// hammering source websites with concurrent/rapid-fire fetches.
const ARTICLE_FETCH_PACING_MS = 500;
// RIPEstat enrichment (server/iocClassification.js#enrichIndicatorAsn) is a
// live network call, reserved for a slow cadence -- capped per cycle so a
// large backlog of "unknown"-classified IPs can't turn one cycle into
// hundreds of sequential lookups.
const MAX_ASN_ENRICHMENTS_PER_CYCLE = 5;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isUnprocessed(link) {
  return !iocIntel.isIocExtractionProcessed(link);
}

/**
 * Real, code-computed co-occurrence check (Phase C) -- an association is
 * only ever attached when the malware/actor/campaign entity stores'
 * ALREADY-INDEPENDENTLY-COMPUTED `articles[]` list (built by
 * combinedExtractionJob.js's separate LLM pass) contains this exact article
 * link. Never inferred here; this function only confirms what two
 * independent passes already agree on. See groundClaims.js for the same
 * "never invent a relationship" discipline applied to AI-authored prose --
 * this is the deterministic-data-layer equivalent.
 */
function statedAssociationsForArticle(articleLink) {
  const malwareFamilies = malwareIntel.getAllEntities().filter((m) => (m.articles ?? []).some((a) => a.link === articleLink)).map((m) => m.name);
  const actors = actorIntel.getAllEntities().filter((a) => (a.articles ?? []).some((art) => art.link === articleLink)).map((a) => a.name);
  const campaigns = campaignIntel.getAllEntities().filter((c) => (c.articles ?? []).some((a) => a.link === articleLink)).map((c) => c.name);
  return { malwareFamilies, actors, campaigns };
}

async function processArticle(article) {
  const fullText = await fetchArticleText(article.link, article.source);
  const extractionMethod = fullText ? "regex-fulltext" : "regex-title-summary";
  const text = fullText ?? `${article.title}\n${article.summary ?? ""}`;

  const extracted = extractEntities(text, {});
  const candidates = iocIntel.flattenExtractedCandidates(extracted);
  const statedAssociations = statedAssociationsForArticle(article.link);

  let validated = 0;
  let duplicates = 0;
  for (const { type, value } of candidates) {
    const normalized = iocIntel.normalizeIndicator(type, value);
    const existingBefore = iocIntel.findIndicator(type, normalized);
    const contextSnippet = extractContextSnippet(text, value);
    const result = iocIntel.upsertIndicator(type, value, {
      articleTitle: article.title,
      articleLink: article.link,
      articleSource: article.source,
      publishedDate: article.publishedDate,
      contextSnippet,
      extractionMethod,
      statedAssociations,
    });
    if (!result) continue;
    if (existingBefore) duplicates += 1;
    else validated += 1;
  }

  return { candidateCount: candidates.length, validated, duplicates };
}

async function enrichUnknownIps() {
  const candidates = iocIntel
    .getAllEntities()
    .filter((e) => e.type === "ipv4" && e.classification === "unknown" && !e.enrichment)
    .slice(0, MAX_ASN_ENRICHMENTS_PER_CYCLE);
  for (const entity of candidates) {
    const enrichment = await enrichIndicatorAsn(entity.value);
    if (enrichment) iocIntel.setEnrichment(entity.id, enrichment);
  }
}

async function runCycle() {
  const newsItems = cache.getEntry("news").data?.items ?? [];
  const unprocessed = newsItems.filter((item) => isUnprocessed(item.link)).slice(0, MAX_ARTICLES_PER_CYCLE);
  if (unprocessed.length === 0) {
    // Nothing new to extract from -- still worth a slow enrichment pass and
    // an association-backfill sweep, both cheap, so the store keeps
    // improving even during a quiet news cycle.
    await enrichUnknownIps();
    const linked = iocIntel.backfillMissingAssociations(malwareIntel.getAllEntities(), actorIntel.getAllEntities(), campaignIntel.getAllEntities());
    if (linked > 0) iocIntel.saveAfterMentions();
    return;
  }

  let totalCandidates = 0;
  let totalValidated = 0;
  let totalDuplicates = 0;
  let totalFailures = 0;
  const bySource = new Map();

  for (const [index, article] of unprocessed.entries()) {
    if (index > 0) await sleep(ARTICLE_FETCH_PACING_MS);
    try {
      const { candidateCount, validated, duplicates } = await processArticle(article);
      totalCandidates += candidateCount;
      totalValidated += validated;
      totalDuplicates += duplicates;
      const s = bySource.get(article.source) ?? { articlesProcessed: 0, candidates: 0, validated: 0 };
      s.articlesProcessed += 1;
      s.candidates += candidateCount;
      s.validated += validated;
      bySource.set(article.source, s);
    } catch (error) {
      totalFailures += 1;
      log.error("ioc-extraction", `failed to process "${article.title.slice(0, 60)}...": ${error.message}`);
    }
    iocIntel.markIocExtractionProcessed(article.link);
  }

  iocIntel.saveAfterMentions();
  const linked = iocIntel.backfillMissingAssociations(malwareIntel.getAllEntities(), actorIntel.getAllEntities(), campaignIntel.getAllEntities());
  if (linked > 0) iocIntel.saveAfterMentions();
  await enrichUnknownIps();

  recordCycle({ articlesProcessed: unprocessed.length, candidates: totalCandidates, validated: totalValidated, duplicates: totalDuplicates, failures: totalFailures, bySource });

  log.info(
    "ioc-extraction",
    `processed ${unprocessed.length} article(s): ${totalCandidates} candidate(s), ${totalValidated} new unique, ${totalDuplicates} already-known, ${totalFailures} failure(s), ${linked} association(s) backfilled`,
  );
}

async function safeCycle() {
  try {
    await runCycle();
  } catch (error) {
    log.error("ioc-extraction", `cycle failed: ${error.message}`);
  }
}

async function loop() {
  await safeCycle();
  setTimeout(loop, CYCLE_INTERVAL_MS);
}

export function startIocExtractionJob() {
  setTimeout(loop, 25_000); // after combinedExtractionJob's own warm-up delay, so the news cache is already populated
}
