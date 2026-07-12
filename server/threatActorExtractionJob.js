// Drains the news pool through threat-actor extraction (see
// server/threatActorExtraction.js) and upserts confirmed names into the
// canonical entity store (server/threatActorIntelligence.js). Own scheduled
// job, separate from server/malwareExtractionJob.js and
// server/attackTechniqueExtractionJob.js -- extraction is one local-LLM call
// per new article, so each of these bounds itself to a small batch per cycle
// rather than serializing all three behind one long-running loop.
import * as cache from "./cache.js";
import { getCommonAttackToolNames } from "./correlationEngine.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "./ransomwareCampaigns.js";
import { extractActorMentions, validateCandidates } from "./threatActorExtraction.js";
import { upsertMention, isArticleProcessed, markArticleProcessed, reconcile, saveAfterMentions } from "./threatActorIntelligence.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { OllamaUnavailableError } from "./rag/ollamaClient.js";
import { log } from "./lib/log.js";

const MAX_ARTICLES_PER_CYCLE = 15; // bounds each cycle to at most 15 local-LLM calls
const CYCLE_INTERVAL_MS = 2 * 60 * 1000;

function buildExclusionSets(attackData) {
  const malwareNamesLower = new Set();
  for (const s of attackData?.software ?? []) for (const n of [s.name, ...(s.aliases ?? [])]) malwareNamesLower.add(n.toLowerCase());
  for (const m of getMalwareEntities()) for (const n of [m.name, ...m.aliases]) malwareNamesLower.add(n.toLowerCase());
  return { malwareNamesLower, toolNamesLower: getCommonAttackToolNames(attackData) };
}

async function runCycle() {
  const items = cache.getEntry("news").data?.items ?? [];
  const unprocessed = items.filter((item) => !isArticleProcessed(item.link)).slice(0, MAX_ARTICLES_PER_CYCLE);
  if (unprocessed.length === 0) return;

  const attackData = cache.getEntry("attack").data;
  const { malwareNamesLower, toolNamesLower } = buildExclusionSets(attackData);

  let extracted = 0;
  let filtered = 0;
  let newEntities = 0;
  let updatedEntities = 0;

  for (const article of unprocessed) {
    try {
      const candidates = await extractActorMentions({ title: article.title, summary: article.summary });
      extracted += candidates.length;
      const validated = validateCandidates(candidates, { articleSource: article.source, knownMalwareNamesLower: malwareNamesLower, knownToolNamesLower: toolNamesLower });
      filtered += candidates.length - validated.length;

      for (const { name, type } of validated) {
        const { isNew } = upsertMention(name, type, article);
        if (isNew) newEntities += 1;
        else updatedEntities += 1;
      }
    } catch (error) {
      if (error instanceof OllamaUnavailableError) throw error; // stop the whole cycle -- Ollama being down affects every remaining article the same way
      log.error("threat-actor-extraction", `failed to process "${article.title.slice(0, 60)}...": ${error.message}`);
    } finally {
      markArticleProcessed(article.link);
    }
  }

  saveAfterMentions();
  if (attackData) reconcile(attackData, getRansomwareCampaigns());

  log.info(
    "threat-actor-extraction",
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
        log.warn("threat-actor-extraction", `${error.message} -- threat actor extraction will report itself unavailable until Ollama is running.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("threat-actor-extraction", `cycle failed: ${error.message}`);
    }
  }
}

export function startThreatActorExtractionJob() {
  setTimeout(safeCycle, 30_000); // staggered after the malware (20s) and technique (25s) extraction jobs' own delays
  setInterval(safeCycle, CYCLE_INTERVAL_MS);
}
