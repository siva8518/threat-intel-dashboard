// Drains the news pool through campaign/operation-name extraction (see
// server/campaignExtraction.js) and upserts confirmed names into the
// canonical entity store (server/campaignIntelligence.js). Own scheduled
// job, separate from the malware/technique/actor extraction jobs -- one
// local-LLM call per new article, bounded to a small batch per cycle.
import * as cache from "./cache.js";
import { extractCampaignMentions, validateCandidates } from "./campaignExtraction.js";
import { upsertMention, isArticleProcessed, markArticleProcessed, reconcile, saveAfterMentions } from "./campaignIntelligence.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "./threatActorIntelligence.js";
import { OllamaUnavailableError } from "./rag/ollamaClient.js";
import { log } from "./lib/log.js";

const MAX_ARTICLES_PER_CYCLE = 15;
const CYCLE_INTERVAL_MS = 2 * 60 * 1000;

function buildExclusionSets(attackData) {
  const actorNamesLower = new Set();
  for (const g of attackData?.groups ?? []) for (const n of [g.name, ...(g.aliases ?? [])]) actorNamesLower.add(n.toLowerCase());
  for (const a of getActorEntities()) for (const n of [a.name, ...a.aliases]) actorNamesLower.add(n.toLowerCase());

  const malwareNamesLower = new Set();
  for (const s of attackData?.software ?? []) for (const n of [s.name, ...(s.aliases ?? [])]) malwareNamesLower.add(n.toLowerCase());
  for (const m of getMalwareEntities()) for (const n of [m.name, ...m.aliases]) malwareNamesLower.add(n.toLowerCase());

  return { actorNamesLower, malwareNamesLower };
}

async function runCycle() {
  const items = cache.getEntry("news").data?.items ?? [];
  const unprocessed = items.filter((item) => !isArticleProcessed(item.link)).slice(0, MAX_ARTICLES_PER_CYCLE);
  if (unprocessed.length === 0) return;

  const attackData = cache.getEntry("attack").data;
  const { actorNamesLower, malwareNamesLower } = buildExclusionSets(attackData);

  let extracted = 0;
  let filtered = 0;
  let newEntities = 0;
  let updatedEntities = 0;

  for (const article of unprocessed) {
    try {
      const candidates = await extractCampaignMentions({ title: article.title, summary: article.summary });
      extracted += candidates.length;
      const validated = validateCandidates(candidates, { articleSource: article.source, knownActorNamesLower: actorNamesLower, knownMalwareNamesLower: malwareNamesLower });
      filtered += candidates.length - validated.length;

      for (const name of validated) {
        const { isNew } = upsertMention(name, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }
    } catch (error) {
      if (error instanceof OllamaUnavailableError) throw error; // stop the whole cycle -- Ollama being down affects every remaining article the same way
      log.error("campaign-extraction", `failed to process "${article.title.slice(0, 60)}...": ${error.message}`);
    } finally {
      markArticleProcessed(article.link);
    }
  }

  saveAfterMentions();
  reconcile(attackData);

  log.info(
    "campaign-extraction",
    `processed ${unprocessed.length} articles: ${extracted} candidate(s) extracted, ${filtered} filtered by validation, ${newEntities} new + ${updatedEntities} updated entit${newEntities + updatedEntities === 1 ? "y" : "ies"}`,
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
        log.warn("campaign-extraction", `${error.message} -- campaign extraction will report itself unavailable until Ollama is running.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("campaign-extraction", `cycle failed: ${error.message}`);
    }
  }
}

export function startCampaignExtractionJob() {
  setTimeout(safeCycle, 35_000); // staggered after the malware (20s), technique (25s), and actor (30s) extraction jobs' own delays
  setInterval(safeCycle, CYCLE_INTERVAL_MS);
}
