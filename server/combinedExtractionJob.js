// Drains the news pool through the combined per-article extraction call (see
// server/combinedExtraction.js, which runs through server/ai/aiRouter.js's
// multi-provider failover) and upserts confirmed entities into all six
// canonical entity stores (malware/
// actor/campaign/technique/dark-web/tool intelligence). Replaces the
// separate jobs that used to each make their own sequential LLM call per
// article (malwareExtractionJob.js, threatActorExtractionJob.js,
// campaignExtractionJob.js, attackTechniqueExtractionJob.js) -- one combined
// call per article cuts the per-article LLM round-trip count, the actual
// throughput bottleneck.
//
// An article only counts as "processed" once all six stores agree it is --
// see isUnprocessed/markProcessedEverywhere below -- so articles the old,
// separate jobs only partially got through before this merge still get a
// full, correctly-merged pass exactly once.
import * as cache from "./cache.js";
import { threatFeedIocs } from "./threatFeed.js";
import { splitFamilies, getCommonAttackToolNames } from "./correlationEngine.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "./ransomwareCampaigns.js";
import { getAllGithubRepos } from "./githubIntel/index.js";
import { extractAllEntities } from "./combinedExtraction.js";
import { extractIocs } from "./aiThreatSummary.js";
import { validateCandidates as validateMalwareCandidates } from "./malwareExtraction.js";
import { validateCandidates as validateActorCandidates } from "./threatActorExtraction.js";
import { validateCandidates as validateCampaignCandidates } from "./campaignExtraction.js";
import { resolveTechniques } from "./attackTechniqueExtraction.js";
import { validateCandidates as validateDarkWebCandidates } from "./darkWebExtraction.js";
import { validateCandidates as validateToolCandidates } from "./toolExtraction.js";
import * as malwareIntel from "./malwareIntelligence.js";
import * as actorIntel from "./threatActorIntelligence.js";
import * as campaignIntel from "./campaignIntelligence.js";
import * as techniqueIntel from "./attackTechniqueIntelligence.js";
import * as darkWebIntel from "./darkWebIntelligence.js";
import * as toolIntel from "./toolIntelligence.js";
import { AllProvidersFailedError } from "./ai/aiRouter.js";
import { log } from "./lib/log.js";

// Was 15 when this job (and its four now-merged predecessors) were designed
// against a ~74-106-source news pool. The pool has since grown to ~196
// sources / ~2900 pooled articles, and 15/cycle at a 2-min interval meant a
// full backlog drain (needed once whenever a new entity type like dark-web
// findings is added, since every store must agree an article is processed)
// would take upwards of 10 hours -- confirmed live, a new store sat at 0
// results for the first several cycles purely from queue depth, not a bug.
// Raised to 40; each combined call is a hosted Groq request, still
// sequential (one in flight at a time) to stay comfortably under Groq's
// free-tier rate limit rather than to work around a slow local model.
const MAX_ARTICLES_PER_CYCLE = 40;
const CYCLE_INTERVAL_MS = 2 * 60 * 1000;

// Confirmed live: with no pacing at all, a healthy provider answers each
// extraction call in well under a second, so a 40-article cycle could fire
// all 40 calls within seconds -- comfortably exceeding every configured
// provider's free-tier per-minute quota (Gemini/Cohere free tiers sit around
// 15-20 RPM) well before the cycle finishes. Once the first-priority
// provider starts rate-limiting mid-cycle, EVERY remaining article's call
// then fails over through all 4 providers in turn, burning through their
// quotas too -- this is the direct cause of interactive requests (the
// Investigation Workspace's AI panels, Industry Intelligence briefings)
// seeing "All AI providers failed" even though each provider is healthy in
// isolation, just already spent for the current minute. Pacing each call
// keeps the whole cycle's request rate under any single provider's typical
// free-tier ceiling without lowering MAX_ARTICLES_PER_CYCLE (which exists
// specifically to keep backlog-drain time bounded -- see that constant's own
// comment) -- a 40-article cycle now takes ~2-3 minutes instead of a few
// seconds, comfortably absorbed by this job's self-rescheduling (never
// overlaps the next cycle; see loop() below).
const ARTICLE_PACING_MS = 4000;
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Malware families with no live indicator behind them at all still get a
// count but no records to show -- that's real ("Magecart" tagged but
// nothing currently in the deduped feed"), not a bug in this function.
const MAX_IOC_RECORDS_PER_FAMILY = 8;

function buildIocFamilyData() {
  const counts = new Map();
  const records = new Map();
  for (const ioc of threatFeedIocs()) {
    for (const family of splitFamilies(ioc.malwareFamily)) {
      const key = malwareIntel.normalizeMalwareId(family);
      counts.set(key, (counts.get(key) ?? 0) + 1);
      const list = records.get(key) ?? [];
      if (list.length < MAX_IOC_RECORDS_PER_FAMILY) {
        list.push({ indicator: ioc.indicator, indicatorType: ioc.indicatorType, sources: ioc.sources, firstSeen: ioc.firstSeen });
        records.set(key, list);
      }
    }
  }
  return { counts, records };
}

function buildExclusionSets(attackData) {
  const actorNamesLower = new Set();
  for (const g of attackData?.groups ?? []) for (const n of [g.name, ...(g.aliases ?? [])]) actorNamesLower.add(n.toLowerCase());
  for (const a of actorIntel.getAllEntities()) for (const n of [a.name, ...a.aliases]) actorNamesLower.add(n.toLowerCase());

  const malwareNamesLower = new Set();
  for (const s of attackData?.software ?? []) for (const n of [s.name, ...(s.aliases ?? [])]) malwareNamesLower.add(n.toLowerCase());
  for (const m of malwareIntel.getAllEntities()) for (const n of [m.name, ...m.aliases]) malwareNamesLower.add(n.toLowerCase());

  return { actorNamesLower, malwareNamesLower, toolNamesLower: getCommonAttackToolNames(attackData) };
}

// Restricted to the 4 canonical types this app already has UI/lookup
// support for everywhere else (IOC Search, VirusTotal links, etc. -- see
// src/types/threat-intel.ts's IocType) rather than the full category set
// extractIocs() can produce -- registry keys/mutexes/etc. have no existing
// home in the Malware Intelligence UI's indicator model, and stretching
// IocType to cover them would ripple through every other IOC display in
// this app for a category this specific feature doesn't need.
function flattenArticleIocs(extracted) {
  const records = [];
  const push = (indicator, indicatorType) => records.push({ indicator, indicatorType });
  for (const ip of extracted.ipAddresses ?? []) push(ip, "ip");
  for (const d of extracted.domains ?? []) push(d, "domain");
  for (const u of extracted.urls ?? []) push(u, "url");
  for (const h of extracted.hashes ?? []) push(h, "hash");
  return records;
}

function isUnprocessed(link) {
  return (
    !malwareIntel.isArticleProcessed(link) ||
    !actorIntel.isArticleProcessed(link) ||
    !campaignIntel.isArticleProcessed(link) ||
    !techniqueIntel.isArticleProcessed(link) ||
    !darkWebIntel.isArticleProcessed(link) ||
    !toolIntel.isArticleProcessed(link)
  );
}

function markProcessedEverywhere(link) {
  malwareIntel.markArticleProcessed(link);
  actorIntel.markArticleProcessed(link);
  campaignIntel.markArticleProcessed(link);
  techniqueIntel.markArticleProcessed(link);
  darkWebIntel.markArticleProcessed(link);
  toolIntel.markArticleProcessed(link);
}

/**
 * GitHub repos reshaped into the same {title, summary, link, source,
 * publishedDate} article shape the rest of this pipeline (and every entity
 * store's upsertMention) already expects -- so a repo's name/description
 * flows through the identical 5-category extraction as a news headline,
 * with no store-side changes needed. This is what lets Dark Web Intelligence
 * (and the other three) pick up findings named in a repo's own description
 * (e.g. a leak-tracker or IOC-feed repo that names a specific leak-site
 * posting), not just from RSS coverage of the same event.
 */
function githubRepoArticles() {
  return getAllGithubRepos().map((repo) => ({
    title: repo.fullName,
    summary: repo.description ?? null,
    link: repo.url,
    source: "GitHub Intel",
    publishedDate: repo.discoveredAt,
  }));
}

// Reserved slots per cycle for GitHub repos, taken off the top before news
// fills the rest. News volume can exceed MAX_ARTICLES_PER_CYCLE on its own
// (fresh RSS items arrive continuously), which would otherwise starve the
// smaller, one-time 434-repo backlog indefinitely since it's always queued
// behind whatever news is currently unprocessed.
const GITHUB_SLOTS_PER_CYCLE = 10;

/**
 * A GitHub repo's "headline" here is its own `owner/repo-name` (see
 * githubRepoArticles() above) -- nothing like a real news headline's prose.
 * Confirmed live this gets misread as if the repo were naming a threat
 * actor: "drkemp187/evadelint" (a defensive Sigma-rule linter -- "score
 * your detection rules by how easily an attacker can evade them") produced
 * two fake "Unknown"-type actor entities, "drkemp187" and "evadelint",
 * neither a real threat actor, both just the repo talking about itself.
 * Strips any candidate that IS the repo's own owner/name before validation
 * ever runs -- the same self-exclusion idea as threatActorExtraction.js's
 * existing articleSource check, extended to the repo's own identity too.
 */
function selfReferenceTokens(article) {
  if (article.source !== "GitHub Intel") return new Set();
  const [owner, repoName] = article.title.split("/");
  return new Set([owner, repoName].filter(Boolean).map((s) => s.toLowerCase()));
}

async function runCycle() {
  const newsItems = cache.getEntry("news").data?.items ?? [];
  const unprocessedRepos = githubRepoArticles()
    .filter((item) => isUnprocessed(item.link))
    .slice(0, GITHUB_SLOTS_PER_CYCLE);
  const unprocessedNews = newsItems
    .filter((item) => isUnprocessed(item.link))
    .slice(0, MAX_ARTICLES_PER_CYCLE - unprocessedRepos.length);
  const unprocessed = [...unprocessedRepos, ...unprocessedNews];
  if (unprocessed.length === 0) return;

  const attackData = cache.getEntry("attack").data;
  const attackIndex = attackData?.techniques ?? [];
  const { actorNamesLower, malwareNamesLower, toolNamesLower } = buildExclusionSets(attackData);

  let extracted = 0;
  let filtered = 0;
  let newEntities = 0;
  let updatedEntities = 0;

  for (const [index, article] of unprocessed.entries()) {
    if (index > 0) await sleep(ARTICLE_PACING_MS);
    try {
      const { malware, actors, campaigns, techniques, darkweb, tools } = await extractAllEntities({ title: article.title, summary: article.summary });
      extracted += malware.length + actors.length + campaigns.length + techniques.length + darkweb.length + tools.length;

      const selfTokens = selfReferenceTokens(article);
      const nonSelfMalware = malware.filter((name) => !selfTokens.has(name.toLowerCase()));
      const nonSelfActors = actors.filter((a) => !selfTokens.has((a.name ?? "").toLowerCase()));
      const nonSelfCampaigns = campaigns.filter((name) => !selfTokens.has(name.toLowerCase()));
      const nonSelfTools = tools.filter((name) => !selfTokens.has(name.toLowerCase()));

      const validMalware = validateMalwareCandidates(nonSelfMalware, { articleSource: article.source, knownActorNamesLower: actorNamesLower, knownToolNamesLower: toolNamesLower });
      // Real IOCs a vendor/researcher published directly in the article's
      // own text (title+summary -- this job doesn't fetch full article text,
      // unlike server/aiThreatSummaryJob.js, to stay cheap across up to 40
      // articles/cycle), attached to every malware family that article
      // mentions -- distinct from and in addition to the bulk-feed-derived
      // `iocs`/`iocSightings` below, which never look at article text at all.
      const articleIocRecords = validMalware.length > 0 ? flattenArticleIocs(extractIocs(`${article.title}\n${article.summary ?? ""}`)) : [];
      for (const name of validMalware) {
        const { entity, isNew } = malwareIntel.upsertMention(name, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
        if (articleIocRecords.length > 0) malwareIntel.addArticleIocs(entity.id, articleIocRecords, article);
      }

      const validActors = validateActorCandidates(nonSelfActors, { articleSource: article.source, knownMalwareNamesLower: malwareNamesLower, knownToolNamesLower: toolNamesLower });
      for (const { name, type } of validActors) {
        const { isNew } = actorIntel.upsertMention(name, type, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }

      const validCampaigns = validateCampaignCandidates(nonSelfCampaigns, { articleSource: article.source, knownActorNamesLower: actorNamesLower, knownMalwareNamesLower: malwareNamesLower });
      for (const name of validCampaigns) {
        const { isNew } = campaignIntel.upsertMention(name, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }

      const sourceText = `${article.title} ${article.summary ?? ""}`;
      const resolvedTechniques = attackIndex.length > 0 ? resolveTechniques(techniques, attackIndex, sourceText) : [];
      for (const technique of resolvedTechniques) techniqueIntel.upsertMention(technique.id, article);

      const validDarkWeb = validateDarkWebCandidates(darkweb, { articleSource: article.source });
      for (const { label, type, platform, victimOrg } of validDarkWeb) {
        const { isNew } = darkWebIntel.upsertMention(label, { type, platform, victimOrg }, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }

      const validTools = validateToolCandidates(nonSelfTools, { articleSource: article.source, knownMalwareNamesLower: malwareNamesLower, knownActorNamesLower: actorNamesLower });
      for (const name of validTools) {
        const { isNew } = toolIntel.upsertMention(name, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }

      filtered +=
        malware.length - validMalware.length +
        actors.length - validActors.length +
        campaigns.length - validCampaigns.length +
        techniques.length - resolvedTechniques.length +
        darkweb.length - validDarkWeb.length +
        tools.length - validTools.length;
    } catch (error) {
      if (error instanceof AllProvidersFailedError) throw error; // stop the whole cycle -- every provider being down/rate-limited affects every remaining article the same way
      log.error("combined-extraction", `failed to process "${article.title.slice(0, 60)}...": ${error.message}`);
    } finally {
      markProcessedEverywhere(article.link);
    }
  }

  malwareIntel.saveAfterMentions();
  actorIntel.saveAfterMentions();
  campaignIntel.saveAfterMentions();
  techniqueIntel.saveAfterMentions();
  darkWebIntel.saveAfterMentions();
  toolIntel.saveAfterMentions();

  if (attackData) {
    const { counts, records } = buildIocFamilyData();
    malwareIntel.reconcile(attackData, counts, records);
    actorIntel.reconcile(attackData, getRansomwareCampaigns());
    toolIntel.reconcile(attackData);
  }
  campaignIntel.reconcile(attackData);
  darkWebIntel.reconcile();

  log.info(
    "combined-extraction",
    `processed ${unprocessed.length} articles: ${extracted} candidate(s) extracted across 6 entity types, ${filtered} filtered by validation, ${newEntities} new + ${updatedEntities} updated entit${newEntities + updatedEntities === 1 ? "y" : "ies"}`,
  );
}

let hasWarnedUnavailable = false;

async function safeCycle() {
  try {
    await runCycle();
    hasWarnedUnavailable = false;
  } catch (error) {
    if (error instanceof AllProvidersFailedError) {
      if (!hasWarnedUnavailable) {
        log.warn("combined-extraction", `${error.message} -- combined extraction will report itself unavailable until at least one AI provider is configured/reachable again.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("combined-extraction", `cycle failed: ${error.message}`);
    }
  }
}

/**
 * Self-rescheduling instead of setInterval: a 40-article cycle can still take
 * a while even against a fast hosted API (sequential, one request in flight
 * at a time, plus each article also runs its own validation/reconcile work).
 * setInterval doesn't wait for the previous
 * async callback, so it would have queued several more overlapping cycles
 * before the first one finished, all re-selecting the same still-unprocessed
 * backlog before any of them could mark it done. Scheduling the next run
 * only after the current one settles guarantees exactly one cycle in flight
 * at a time.
 */
async function loop() {
  await safeCycle();
  setTimeout(loop, CYCLE_INTERVAL_MS);
}

export function startCombinedExtractionJob() {
  setTimeout(loop, 20_000); // after the RAG indexer's own 10s delay, so news/attack caches are warm
}
