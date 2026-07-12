// Persisted store of ATT&CK technique mentions automatically extracted from
// news article text (see server/attackTechniqueExtraction.js) -- the same
// "extract from articles, remember it, never re-lose it on the next request"
// pattern as server/malwareIntelligence.js. Feeds server/correlate.js's
// tactic heatmap and technique-frequency tables as a second source alongside
// the existing curated malware-to-technique map, so a technique named in
// vendor coverage shows up even when no IOC in the live feed happens to
// carry a malware-family tag the static map recognizes.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "attack-technique-mentions.json");
const MAX_ARTICLES_PER_TECHNIQUE = 25;

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return {
      mentions: parsed.mentions && typeof parsed.mentions === "object" ? parsed.mentions : {},
      processedArticleIds: Array.isArray(parsed.processedArticleIds) ? parsed.processedArticleIds : [],
    };
  } catch {
    return { mentions: {}, processedArticleIds: [] }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  const trimmed = { ...state, processedArticleIds: state.processedArticleIds.slice(-5000) };
  fs.writeFileSync(STORE_PATH, JSON.stringify(trimmed), "utf-8");
}

export function isArticleProcessed(articleId) {
  return state.processedArticleIds.includes(articleId);
}

export function markArticleProcessed(articleId) {
  if (!state.processedArticleIds.includes(articleId)) state.processedArticleIds.push(articleId);
}

/** Records one technique mention from one article -- dedup by article link, same as malwareIntelligence.js#upsertMention. */
export function upsertMention(techniqueId, article) {
  const entry = state.mentions[techniqueId] ?? { count: 0, articles: [] };
  const alreadyLinked = entry.articles.some((a) => a.link === article.link);
  if (!alreadyLinked) {
    entry.articles.unshift({ title: article.title, link: article.link, source: article.source, publishedDate: article.publishedDate });
    entry.articles = entry.articles.slice(0, MAX_ARTICLES_PER_TECHNIQUE);
    entry.count += 1;
  }
  state.mentions[techniqueId] = entry;
}

/** Map<techniqueId, count> -- the shape server/correlate.js's aggregation functions merge in alongside IOC-derived counts. */
export function getNewsTechniqueCounts() {
  return new Map(Object.entries(state.mentions).map(([id, entry]) => [id, entry.count]));
}

export function getArticlesForTechnique(techniqueId) {
  return state.mentions[techniqueId]?.articles ?? [];
}

export function saveAfterMentions() {
  persist();
}
