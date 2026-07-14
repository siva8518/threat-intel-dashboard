// Canonical dark-web-finding entity store -- the "one record per finding"
// backbone for the Dark Web Intelligence page and the RAG chatbot, mirroring
// server/campaignIntelligence.js. Every finding ever extracted from news
// (server/darkWebExtraction.js, via the combined per-article call in
// server/combinedExtraction.js) gets exactly one record here, persisted to
// disk, enriched over time.
//
// This store contains NO direct dark-web-forum scraping. Every record
// originates from an OSINT source in server/connectors/newsFeeds.js's
// FEEDS list -- a vendor or researcher who monitors underground forums/
// marketplaces/Telegram channels and publishes what they saw (KELA, Cyble,
// SOCRadar, Constella Intelligence, Silobreaker, Recorded Future, Intel 471,
// ransomware leak-site trackers, etc.). Like campaigns, a dark-web finding
// has no authoritative catalog to verify against, so `verified` here means
// corroborated by at least two independently-published sources, the same
// self-contained signal campaignIntelligence.js uses.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { matchCveIds, matchIndustries, matchCountries } from "./newsCorrelation.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "./threatActorIntelligence.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "darkweb-intelligence.json");
const MAX_ARTICLES_PER_ENTITY = 25;

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return {
      entities: Array.isArray(parsed.entities) ? parsed.entities : [],
      processedArticleIds: Array.isArray(parsed.processedArticleIds) ? parsed.processedArticleIds : [],
    };
  } catch {
    return { entities: [], processedArticleIds: [] }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  const trimmed = { ...state, processedArticleIds: state.processedArticleIds.slice(-5000) };
  fs.writeFileSync(STORE_PATH, JSON.stringify(trimmed), "utf-8");
}

/** Stable id for dedup -- lowercase, whitespace-collapsed, exact-match only (same policy as the other intelligence stores). */
export function normalizeFindingId(label) {
  return label.trim().toLowerCase().replace(/\s+/g, " ");
}

export function isArticleProcessed(articleId) {
  return state.processedArticleIds.includes(articleId);
}

export function markArticleProcessed(articleId) {
  if (!state.processedArticleIds.includes(articleId)) state.processedArticleIds.push(articleId);
}

function mergeUnique(existing, incoming) {
  const set = new Set(existing);
  for (const item of incoming) if (item) set.add(item);
  return Array.from(set);
}

/**
 * Records one dark-web finding from one article -- creates a new record or
 * merges into the existing one for that label. `platform`/`victimOrg` fill
 * in only if the existing record doesn't already have one (first source to
 * name it wins, later sources can't blank it out). Also derives
 * targetedIndustries/targetedCountries/cveExploited directly from this
 * article's own text, same as the other three intelligence stores.
 */
export function upsertMention(rawLabel, { type, platform, victimOrg }, article) {
  const id = normalizeFindingId(rawLabel);
  let entity = state.entities.find((e) => e.id === id);
  const isNew = !entity;

  if (!entity) {
    entity = {
      id,
      name: rawLabel.trim(),
      aliases: [],
      type,
      platform: platform ?? null,
      victimOrg: victimOrg ?? null,
      verified: false,
      associatedActors: [],
      associatedMalware: [],
      targetedIndustries: [],
      targetedCountries: [],
      cveExploited: [],
      firstSeen: article.publishedDate,
      lastSeen: article.publishedDate,
      mentionCount: 0,
      articles: [],
    };
    state.entities.push(entity);
  }

  if (rawLabel.trim() !== entity.name && !entity.aliases.includes(rawLabel.trim())) {
    entity.aliases.push(rawLabel.trim());
  }
  if (!entity.platform && platform) entity.platform = platform;
  if (!entity.victimOrg && victimOrg) entity.victimOrg = victimOrg;

  const alreadyLinked = entity.articles.some((a) => a.link === article.link);
  if (!alreadyLinked) {
    entity.articles.unshift({ title: article.title, link: article.link, source: article.source, publishedDate: article.publishedDate });
    entity.articles = entity.articles.slice(0, MAX_ARTICLES_PER_ENTITY);
    entity.mentionCount += 1;

    const text = `${article.title} ${article.summary ?? ""}`;
    entity.targetedIndustries = mergeUnique(entity.targetedIndustries, matchIndustries(text));
    entity.targetedCountries = mergeUnique(entity.targetedCountries, matchCountries(text));
    entity.cveExploited = mergeUnique(entity.cveExploited, matchCveIds(text));
  }

  if (new Date(article.publishedDate) > new Date(entity.lastSeen)) entity.lastSeen = article.publishedDate;
  if (new Date(article.publishedDate) < new Date(entity.firstSeen)) entity.firstSeen = article.publishedDate;

  return { entity, isNew };
}

/**
 * Enriches every record: cross-references server/threatActorIntelligence.js
 * and server/malwareIntelligence.js's own entities for actor/malware<->finding
 * co-mentions in the same article -- the same co-mention mechanism
 * campaignIntelligence.js uses. `verified` means corroborated by at least
 * two independently-published sources -- there's no authoritative catalog of
 * dark-web activity to match against, so corroboration is the whole signal.
 */
export function reconcile() {
  for (const entity of state.entities) {
    const ownArticleLinks = new Set(entity.articles.map((a) => a.link));
    if (ownArticleLinks.size > 0) {
      for (const actor of getActorEntities()) {
        if (actor.articles.some((a) => ownArticleLinks.has(a.link))) {
          entity.associatedActors = mergeUnique(entity.associatedActors, [actor.name]);
        }
      }
      for (const malware of getMalwareEntities()) {
        if (malware.articles.some((a) => ownArticleLinks.has(a.link))) {
          entity.associatedMalware = mergeUnique(entity.associatedMalware, [malware.name]);
        }
      }
    }

    const distinctSources = new Set(entity.articles.map((a) => a.source));
    entity.verified = distinctSources.size >= 2;
  }

  persist();
}

export function getAllEntities() {
  return [...state.entities].sort((a, b) => {
    if (a.verified !== b.verified) return a.verified ? -1 : 1;
    return new Date(b.lastSeen) - new Date(a.lastSeen);
  });
}

export function saveAfterMentions() {
  persist();
}
