// Drains the news pool through the combined per-article extraction call (see
// server/combinedExtraction.js) and upserts confirmed entities into all five
// canonical entity stores (malware/actor/campaign/technique/dark-web
// intelligence). Replaces the four separate jobs that used to each make
// their own sequential local-LLM call per article (malwareExtractionJob.js,
// threatActorExtractionJob.js, campaignExtractionJob.js,
// attackTechniqueExtractionJob.js) -- one combined call per article cuts the
// per-article LLM round-trip count 5x, the actual throughput bottleneck
// (each call blocks on a local model, not a fast network request).
//
// An article only counts as "processed" once all five stores agree it is --
// see isUnprocessed/markProcessedEverywhere below -- so articles the old,
// separate jobs only partially got through before this merge still get a
// full, correctly-merged pass exactly once.
import * as cache from "./cache.js";
import { threatFeedIocs } from "./threatFeed.js";
import { splitFamilies, getCommonAttackToolNames } from "./correlationEngine.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "./ransomwareCampaigns.js";
import { extractAllEntities } from "./combinedExtraction.js";
import { validateCandidates as validateMalwareCandidates } from "./malwareExtraction.js";
import { validateCandidates as validateActorCandidates } from "./threatActorExtraction.js";
import { validateCandidates as validateCampaignCandidates } from "./campaignExtraction.js";
import { resolveTechniques } from "./attackTechniqueExtraction.js";
import { validateCandidates as validateDarkWebCandidates } from "./darkWebExtraction.js";
import * as malwareIntel from "./malwareIntelligence.js";
import * as actorIntel from "./threatActorIntelligence.js";
import * as campaignIntel from "./campaignIntelligence.js";
import * as techniqueIntel from "./attackTechniqueIntelligence.js";
import * as darkWebIntel from "./darkWebIntelligence.js";
import { OllamaUnavailableError } from "./rag/ollamaClient.js";
import { log } from "./lib/log.js";

const MAX_ARTICLES_PER_CYCLE = 15;
const CYCLE_INTERVAL_MS = 2 * 60 * 1000;

function buildIocFamilyCounts() {
  const counts = new Map();
  for (const ioc of threatFeedIocs()) {
    for (const family of splitFamilies(ioc.malwareFamily)) {
      const key = malwareIntel.normalizeMalwareId(family);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }
  return counts;
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

function isUnprocessed(link) {
  return (
    !malwareIntel.isArticleProcessed(link) ||
    !actorIntel.isArticleProcessed(link) ||
    !campaignIntel.isArticleProcessed(link) ||
    !techniqueIntel.isArticleProcessed(link) ||
    !darkWebIntel.isArticleProcessed(link)
  );
}

function markProcessedEverywhere(link) {
  malwareIntel.markArticleProcessed(link);
  actorIntel.markArticleProcessed(link);
  campaignIntel.markArticleProcessed(link);
  techniqueIntel.markArticleProcessed(link);
  darkWebIntel.markArticleProcessed(link);
}

async function runCycle() {
  const items = cache.getEntry("news").data?.items ?? [];
  const unprocessed = items.filter((item) => isUnprocessed(item.link)).slice(0, MAX_ARTICLES_PER_CYCLE);
  if (unprocessed.length === 0) return;

  const attackData = cache.getEntry("attack").data;
  const attackIndex = attackData?.techniques ?? [];
  const { actorNamesLower, malwareNamesLower, toolNamesLower } = buildExclusionSets(attackData);

  let extracted = 0;
  let filtered = 0;
  let newEntities = 0;
  let updatedEntities = 0;

  for (const article of unprocessed) {
    try {
      const { malware, actors, campaigns, techniques, darkweb } = await extractAllEntities({ title: article.title, summary: article.summary });
      extracted += malware.length + actors.length + campaigns.length + techniques.length + darkweb.length;

      const validMalware = validateMalwareCandidates(malware, { articleSource: article.source, knownActorNamesLower: actorNamesLower, knownToolNamesLower: toolNamesLower });
      for (const name of validMalware) {
        const { isNew } = malwareIntel.upsertMention(name, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }

      const validActors = validateActorCandidates(actors, { articleSource: article.source, knownMalwareNamesLower: malwareNamesLower, knownToolNamesLower: toolNamesLower });
      for (const { name, type } of validActors) {
        const { isNew } = actorIntel.upsertMention(name, type, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }

      const validCampaigns = validateCampaignCandidates(campaigns, { articleSource: article.source, knownActorNamesLower: actorNamesLower, knownMalwareNamesLower: malwareNamesLower });
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

      filtered +=
        malware.length - validMalware.length +
        actors.length - validActors.length +
        campaigns.length - validCampaigns.length +
        techniques.length - resolvedTechniques.length +
        darkweb.length - validDarkWeb.length;
    } catch (error) {
      if (error instanceof OllamaUnavailableError) throw error; // stop the whole cycle -- Ollama being down affects every remaining article the same way
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

  if (attackData) {
    malwareIntel.reconcile(attackData, buildIocFamilyCounts());
    actorIntel.reconcile(attackData, getRansomwareCampaigns());
  }
  campaignIntel.reconcile(attackData);
  darkWebIntel.reconcile();

  log.info(
    "combined-extraction",
    `processed ${unprocessed.length} articles: ${extracted} candidate(s) extracted across 5 entity types, ${filtered} filtered by validation, ${newEntities} new + ${updatedEntities} updated entit${newEntities + updatedEntities === 1 ? "y" : "ies"}`,
  );
}

let hasWarnedUnavailable = false;

async function safeCycle() {
  try {
    await runCycle();
    hasWarnedUnavailable = false;
  } catch (error) {
    if (error instanceof OllamaUnavailableError) {
      if (!hasWarnedUnavailable) {
        log.warn("combined-extraction", `${error.message} -- combined extraction will report itself unavailable until Ollama is running.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("combined-extraction", `cycle failed: ${error.message}`);
    }
  }
}

export function startCombinedExtractionJob() {
  setTimeout(safeCycle, 20_000); // after the RAG indexer's own 10s delay, so news/attack caches are warm
  setInterval(safeCycle, CYCLE_INTERVAL_MS);
}
