// Drains the news pool through ATT&CK technique-mention extraction (see
// server/attackTechniqueExtraction.js) and records confirmed mentions into
// server/attackTechniqueIntelligence.js. Own scheduled job, separate from
// server/malwareExtractionJob.js, for the same reason that one is separate
// from the RAG indexer -- one local-LLM call per new article, bounded to a
// small batch per cycle so it doesn't block on dozens of sequential calls.
import * as cache from "./cache.js";
import { extractTechniqueMentions, resolveTechniques } from "./attackTechniqueExtraction.js";
import { upsertMention, isArticleProcessed, markArticleProcessed, saveAfterMentions } from "./attackTechniqueIntelligence.js";
import { OllamaUnavailableError } from "./rag/ollamaClient.js";
import { log } from "./lib/log.js";

const MAX_ARTICLES_PER_CYCLE = 15;
const CYCLE_INTERVAL_MS = 2 * 60 * 1000;

async function runCycle() {
  const attackIndex = cache.getEntry("attack").data?.techniques ?? [];
  if (attackIndex.length === 0) return; // nothing to validate extracted candidates against yet

  const items = cache.getEntry("news").data?.items ?? [];
  const unprocessed = items.filter((item) => !isArticleProcessed(item.link)).slice(0, MAX_ARTICLES_PER_CYCLE);
  if (unprocessed.length === 0) return;

  let extracted = 0;
  let resolved = 0;

  for (const article of unprocessed) {
    try {
      const candidates = await extractTechniqueMentions({ title: article.title, summary: article.summary });
      extracted += candidates.length;
      const sourceText = `${article.title} ${article.summary ?? ""}`;
      const techniques = resolveTechniques(candidates, attackIndex, sourceText);
      resolved += techniques.length;
      for (const technique of techniques) upsertMention(technique.id, article);
    } catch (error) {
      if (error instanceof OllamaUnavailableError) throw error; // stop the whole cycle -- Ollama being down affects every remaining article the same way
      log.error("attack-technique-extraction", `failed to process "${article.title.slice(0, 60)}...": ${error.message}`);
    } finally {
      markArticleProcessed(article.link);
    }
  }

  saveAfterMentions();
  log.info(
    "attack-technique-extraction",
    `processed ${unprocessed.length} articles: ${extracted} candidate(s) extracted, ${resolved} resolved against ATT&CK`,
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
        log.warn("attack-technique-extraction", `${error.message} -- technique extraction will report itself unavailable until Ollama is running.`);
        hasWarnedUnavailable = true;
      }
    } else {
      log.error("attack-technique-extraction", `cycle failed: ${error.message}`);
    }
  }
}

export function startAttackTechniqueExtractionJob() {
  setTimeout(safeCycle, 25_000); // staggered slightly after the malware extraction job's own 20s delay
  setInterval(safeCycle, CYCLE_INTERVAL_MS);
}
