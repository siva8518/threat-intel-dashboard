// Canonical campaign/operation entity store -- the "one record per named
// campaign" backbone for the Campaign Intelligence page and the RAG
// chatbot, mirroring server/malwareIntelligence.js and
// server/threatActorIntelligence.js. Every campaign name ever extracted
// from news (server/campaignExtraction.js) gets exactly one record here,
// persisted to disk, enriched over time.
//
// Unlike malware/actors, this store does NOT seed from MITRE ATT&CK's own
// Campaigns list -- confirmed live (server/connectors/attack.js) that
// ATT&CK gives campaigns no real display name at all, just their STIX code
// (e.g. "C0027"), so there's nothing meaningful to seed records with or
// match display names against. Enrichment against ATT&CK is instead a
// best-effort description-text search (does any ATT&CK campaign's own
// description mention this name?), not the primary source of truth the way
// it is for malware/actors.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { matchCveIds, matchCountries } from "./newsCorrelation.js";
import { taggingIndustries as matchIndustries } from "./industryClassification.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "./threatActorIntelligence.js";
import { withinDays } from "./lib/dateWindow.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "campaign-intelligence.json");
const MAX_ARTICLES_PER_ENTITY = 25;
// See server/threatActorIntelligence.js's own RECENT_WINDOW_DAYS for the
// full rationale -- kept identical here so an actor and its own campaigns
// agree on what "recent" means.
export const RECENT_WINDOW_DAYS = 180;

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

/** Stable id for dedup -- lowercase, whitespace-collapsed, exact-match only (same policy as the other two intelligence stores). */
export function normalizeCampaignId(name) {
  return name.trim().toLowerCase().replace(/\s+/g, " ");
}

export function isArticleProcessed(articleId) {
  return state.processedArticleIds.includes(articleId);
}

export function markArticleProcessed(articleId) {
  if (!state.processedArticleIds.includes(articleId)) state.processedArticleIds.push(articleId);
}

function mergeUnique(existing, incoming) {
  const set = new Set(existing);
  for (const item of incoming) set.add(item);
  return Array.from(set);
}

/**
 * Records one campaign mention from one article -- creates a new record or
 * merges into the existing one for that name. Also derives
 * targetedIndustries/targetedCountries/cveExploited directly from this
 * article's own text, same as server/threatActorIntelligence.js#upsertMention.
 */
export function upsertMention(rawName, article) {
  const id = normalizeCampaignId(rawName);
  let entity = state.entities.find((e) => e.id === id);
  const isNew = !entity;

  if (!entity) {
    entity = {
      id,
      name: rawName.trim(),
      aliases: [],
      description: null,
      attackId: null,
      attackUrl: null,
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

  if (rawName.trim() !== entity.name && !entity.aliases.includes(rawName.trim())) {
    entity.aliases.push(rawName.trim());
  }

  const alreadyLinked = entity.articles.some((a) => a.link === article.link);
  if (!alreadyLinked) {
    const text = `${article.title} ${article.summary ?? ""}`;
    const industries = matchIndustries(text);
    const countries = matchCountries(text);
    const cves = matchCveIds(text);
    // Per-article match results stay on the article record itself -- see
    // server/threatActorIntelligence.js#upsertMention's own comment for why
    // (recentSignal() below needs this to answer "what has this campaign
    // targeted RECENTLY" instead of an all-time flat union).
    entity.articles.unshift({ title: article.title, link: article.link, source: article.source, publishedDate: article.publishedDate, industries, countries, cves });
    entity.articles = entity.articles.slice(0, MAX_ARTICLES_PER_ENTITY);
    entity.mentionCount += 1;

    entity.targetedIndustries = mergeUnique(entity.targetedIndustries, industries);
    entity.targetedCountries = mergeUnique(entity.targetedCountries, countries);
    entity.cveExploited = mergeUnique(entity.cveExploited, cves);
  }

  if (new Date(article.publishedDate) > new Date(entity.lastSeen)) entity.lastSeen = article.publishedDate;
  if (new Date(article.publishedDate) < new Date(entity.firstSeen)) entity.firstSeen = article.publishedDate;

  return { entity, isNew };
}

/**
 * Enriches every record: a best-effort MITRE ATT&CK Campaigns match (does
 * any ATT&CK campaign's own description mention this name?), plus
 * cross-referencing server/threatActorIntelligence.js and
 * server/malwareIntelligence.js's own entities for actor/malware<->campaign
 * co-mentions -- if an actor or malware family and this campaign were both
 * named in the same article, that's linked here, the same mechanism behind
 * "Show actors using Bumblebee" for the actor store.
 *
 * `verified` here doesn't mean "confirmed by an authoritative catalog" the
 * way it does for malware/actors (ATT&CK's own Campaigns list has no real
 * display names to match against, see the top of this file) -- it means
 * corroborated by at least two independently-published sources, a
 * self-contained signal that doesn't depend on ATT&CK's naming gap.
 */
export function reconcile(attackData) {
  const attackCampaigns = attackData?.campaigns ?? [];

  for (const entity of state.entities) {
    const candidates = [entity.name, ...entity.aliases].map((n) => n.toLowerCase());

    if (!entity.attackId) {
      const match = attackCampaigns.find((c) => candidates.some((n) => (c.description ?? "").toLowerCase().includes(n)));
      if (match) {
        entity.attackId = match.attackId;
        entity.attackUrl = match.url ?? null;
        entity.description = entity.description || match.description || null;
        entity.cveExploited = mergeUnique(entity.cveExploited, match.cveIds ?? []);
      }
    }

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
    entity.verified = Boolean(entity.attackId) || distinctSources.size >= 2;
  }

  persist();
}

export function getAllEntities() {
  return [...state.entities].sort((a, b) => {
    if (a.verified !== b.verified) return a.verified ? -1 : 1;
    return new Date(b.lastSeen) - new Date(a.lastSeen);
  });
}

/** Same as server/threatActorIntelligence.js#recentSignal, for a campaign entity. */
export function recentSignal(entity, days = RECENT_WINDOW_DAYS) {
  const recentArticles = (entity.articles ?? []).filter((a) => withinDays(a.publishedDate, days));
  const industries = new Set();
  const countries = new Set();
  const cves = new Set();
  let mostRecentDate = null;
  for (const a of recentArticles) {
    for (const i of a.industries ?? []) industries.add(i);
    for (const c of a.countries ?? []) countries.add(c);
    for (const cve of a.cves ?? []) cves.add(cve);
    if (!mostRecentDate || new Date(a.publishedDate) > new Date(mostRecentDate)) mostRecentDate = a.publishedDate;
  }
  return {
    windowDays: days,
    articleCount: recentArticles.length,
    mostRecentDate,
    targetedIndustries: Array.from(industries),
    targetedCountries: Array.from(countries),
    cveExploited: Array.from(cves),
    sourceArticles: recentArticles.slice(0, 10).map((a) => ({ title: a.title, link: a.link, source: a.source, publishedDate: a.publishedDate })),
  };
}

/** Same one-time migration as server/threatActorIntelligence.js#backfillArticleRecency, for campaign entities. */
export function backfillArticleRecency() {
  let updated = 0;
  for (const entity of state.entities) {
    for (const a of entity.articles) {
      if (a.industries !== undefined) continue;
      a.industries = matchIndustries(a.title);
      a.countries = matchCountries(a.title);
      a.cves = matchCveIds(a.title);
      updated++;
    }
  }
  if (updated > 0) persist();
  return updated;
}

/**
 * One-time (per taxonomy change) unconditional recompute of every stored
 * article's `industries` field -- see threatActorIntelligence.js's own
 * backfillIndustryClassification for the full rationale (same pattern,
 * mirrored here). countries/cves are untouched.
 */
export function backfillIndustryClassification() {
  let updated = 0;
  for (const entity of state.entities) {
    const rebuilt = new Set();
    for (const a of entity.articles) {
      a.industries = matchIndustries(a.title);
      for (const i of a.industries) rebuilt.add(i);
      updated++;
    }
    entity.targetedIndustries = [...rebuilt];
  }
  if (updated > 0) persist();
  return updated;
}

export function saveAfterMentions() {
  persist();
}
