// Canonical, source-agnostic IOC (indicator of compromise) store -- the
// missing storage layer this app's IOC pipeline never had. Before this file,
// an extracted indicator only had a home if server/combinedExtractionJob.js's
// separate LLM pass ALSO independently named a malware family for the same
// article (see server/malwareIntelligence.js#addArticleIocs); an article
// about a threat actor, campaign, or vulnerability with no confidently-named
// malware family got zero IOC storage even though extraction technically
// ran. This store follows the exact same lifecycle contract as the other
// entity stores (server/malwareIntelligence.js / threatActorIntelligence.js /
// campaignIntelligence.js / darkWebIntelligence.js / toolIntelligence.js) --
// load()/persist() to a flat JSON file, upsertX, getAllEntities() -- but is
// keyed by INDICATOR VALUE, not by any one entity's identity, so any
// indicator extracted from any article's full text has somewhere to live
// regardless of what else that article did or didn't name.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyIndicator, CLASSIFICATIONS } from "./iocClassification.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "ioc-intelligence.json");

// Same rationale as MAX_ARTICLES_PER_ENTITY in the other entity stores -- a
// widely-reported indicator (seen in 40+ vendor reports) shouldn't grow its
// source-citation list unbounded; sightingCount keeps counting past this cap
// even once the citation list itself stops growing, so "how many sources"
// stays accurate even when "which sources, in full" is truncated.
const MAX_SOURCES_PER_INDICATOR = 40;

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
  // Same trim-on-persist pattern as malwareIntelligence.js -- this ledger
  // only needs to cover articles still present in the live news pool.
  const trimmed = { ...state, processedArticleIds: state.processedArticleIds.slice(-5000) };
  fs.writeFileSync(STORE_PATH, JSON.stringify(trimmed), "utf-8");
}

/**
 * Maps server/githubIntel/extractor.js#extractEntities()'s raw output keys
 * to this store's {type, category} pair. `type` is the fine-grained value
 * (sha256 vs sha1 vs md5, ipv4 vs ipv6 kept distinct); `category` is the
 * coarser grouping used for display/filtering. Deliberately excludes
 * attackTechniques/attackTactics/threatActorNames/malwareFamilies (those are
 * entity/context signals with their own dedicated stores already --
 * server/attackTechniqueIntelligence.js, server/threatActorIntelligence.js,
 * server/malwareIntelligence.js -- not indicators in their own right) and
 * yaraRuleNames/sigmaRuleIds (detection-content references, already surfaced
 * via server/correlate.js#detectionRulesFor, not threat observables).
 */
const TYPE_MAP = {
  cveIds: ["cve", "cve"],
  cweIds: ["cwe", "cwe"],
  sha256: ["sha256", "hash"],
  sha1: ["sha1", "hash"],
  md5: ["md5", "hash"],
  ipv4: ["ipv4", "ip"],
  ipv6: ["ipv6", "ip"],
  domains: ["domain", "domain"],
  urls: ["url", "url"],
  emails: ["email", "email"],
  registryKeys: ["registryKey", "registryKey"],
  filePaths: ["filePath", "filePath"],
  linuxPaths: ["filePath", "filePath"],
  fileNames: ["fileName", "fileName"],
  ports: ["port", "port"],
  eventIds: ["eventId", "eventId"],
  namedPipes: ["namedPipe", "namedPipe"],
  userAgents: ["userAgent", "userAgent"],
  cliCommands: ["cliCommand", "cliCommand"],
  mutexes: ["mutex", "mutex"],
  scheduledTasks: ["scheduledTask", "scheduledTask"],
  services: ["service", "service"],
};
export { TYPE_MAP };

/**
 * Reshapes one extractEntities() result into the flat [{type, value}]
 * candidate list this store's upsertIndicator() consumes -- shared by
 * server/iocExtractionJob.js (Phase B) and scripts/backfillIocIntelligence.js
 * (Phase F) so both walk the exact same type list.
 */
export function flattenExtractedCandidates(extracted) {
  const candidates = [];
  for (const [extractorKey, [type]] of Object.entries(TYPE_MAP)) {
    for (const value of extracted[extractorKey] ?? []) candidates.push({ type, value });
  }
  return candidates;
}

export function categoryForType(type) {
  const entry = Object.values(TYPE_MAP).find(([t]) => t === type);
  return entry ? entry[1] : type;
}

/** Normalizes a raw extracted value for dedup/display -- case and trailing-punctuation only, never reshapes the value's actual content. */
export function normalizeIndicator(type, value) {
  const v = (value ?? "").toString().trim();
  if (type === "domain") return v.toLowerCase().replace(/\.+$/, "");
  if (type === "email" || type === "sha256" || type === "sha1" || type === "md5") return v.toLowerCase();
  if (type === "cve" || type === "cwe") return v.toUpperCase();
  return v;
}

export function canonicalId(type, normalizedValue) {
  return `${type}:${normalizedValue}`;
}

function normList(list) {
  return (list ?? []).filter(Boolean).map((v) => v.toString().trim());
}

function mergeAssociations(target, incoming) {
  for (const key of ["malwareFamilies", "actors", "campaigns", "industries", "countries"]) {
    const existing = target[key] ?? (target[key] = []);
    for (const v of normList(incoming?.[key])) if (!existing.includes(v)) existing.push(v);
  }
}

/**
 * Merges one extracted candidate into the canonical store.
 * @param {string} type - fine-grained type (e.g. "sha256", "ipv4", "domain")
 * @param {string} rawValue - the extracted value, pre-normalization
 * @param {{articleTitle:string, articleLink:string, articleSource:string, publishedDate:string, contextSnippet:string|null, extractionMethod:string, statedAssociations?:object}} source
 */
export function upsertIndicator(type, rawValue, source) {
  const value = normalizeIndicator(type, rawValue);
  if (!value) return null;
  const id = canonicalId(type, value);
  let entity = state.entities.find((e) => e.id === id);
  const isNew = !entity;

  if (!entity) {
    const { classification, reason, confidence } = classifyIndicator(type, value, source.contextSnippet);
    entity = {
      id,
      type,
      category: categoryForType(type),
      value,
      classification,
      classificationReason: reason,
      confidence,
      extractionMethod: source.extractionMethod ?? "regex-title-summary",
      firstSeen: source.publishedDate ?? new Date().toISOString(),
      lastSeen: source.publishedDate ?? new Date().toISOString(),
      sightingCount: 0,
      sources: [],
      aggregatedAssociations: { malwareFamilies: [], actors: [], campaigns: [], industries: [], countries: [] },
      enrichment: null,
    };
    state.entities.push(entity);
  }

  const alreadyLinked = entity.sources.some((s) => s.articleLink === source.articleLink);
  if (!alreadyLinked) {
    entity.sightingCount += 1;
    if (entity.sources.length < MAX_SOURCES_PER_INDICATOR) {
      entity.sources.unshift({
        articleTitle: source.articleTitle ?? null,
        articleLink: source.articleLink ?? null,
        articleSource: source.articleSource ?? null,
        publishedDate: source.publishedDate ?? null,
        contextSnippet: source.contextSnippet ?? null,
        extractionMethod: source.extractionMethod ?? "regex-title-summary",
      });
    }
  }

  if (source.publishedDate) {
    if (new Date(source.publishedDate) > new Date(entity.lastSeen)) entity.lastSeen = source.publishedDate;
    if (new Date(source.publishedDate) < new Date(entity.firstSeen)) entity.firstSeen = source.publishedDate;
  }

  if (source.statedAssociations) mergeAssociations(entity.aggregatedAssociations, source.statedAssociations);

  // A full-text extraction pass re-observing an indicator this store already
  // has (from a title+summary-only pass) is real, additional evidence --
  // upgrade extractionMethod so downstream consumers know a fuller pass has
  // confirmed it, never downgrade an already-fulltext record.
  if (source.extractionMethod === "regex-fulltext" && entity.extractionMethod !== "regex-fulltext") {
    entity.extractionMethod = "regex-fulltext";
  }

  return { entity, isNew };
}

/** Attaches a lazily-computed ASN/holder enrichment (see server/iocClassification.js#enrichIndicatorAsn) onto an existing record -- cached indefinitely once set. */
export function setEnrichment(id, enrichment) {
  const entity = state.entities.find((e) => e.id === id);
  if (entity) entity.enrichment = enrichment;
}

/**
 * Opportunistic association backfill (Phase C) -- for every canonical
 * record with no stated associations yet, checks whether any of its own
 * source articles is ALSO present in the malware/actor/campaign entity
 * stores' own `articles[]` lists (real, code-computed co-occurrence, the
 * same discipline server/investigation/groundClaims.js enforces elsewhere in
 * this app: never infer a relationship, only ever confirm one two
 * independent passes already agree on). Cheap -- in-memory Array.some() over
 * already-loaded stores, no I/O.
 */
export function backfillMissingAssociations(malwareEntities, actorEntities, campaignEntities) {
  let linked = 0;
  for (const entity of state.entities) {
    const hasAssociations = Object.values(entity.aggregatedAssociations ?? {}).some((list) => list.length > 0);
    if (hasAssociations) continue;
    const links = new Set(entity.sources.map((s) => s.articleLink).filter(Boolean));
    if (links.size === 0) continue;

    const matchedMalware = malwareEntities.filter((m) => (m.articles ?? []).some((a) => links.has(a.link))).map((m) => m.name);
    const matchedActors = actorEntities.filter((a) => (a.articles ?? []).some((art) => links.has(art.link))).map((a) => a.name);
    const matchedCampaigns = campaignEntities.filter((c) => (c.articles ?? []).some((a) => links.has(a.link))).map((c) => c.name);

    if (matchedMalware.length || matchedActors.length || matchedCampaigns.length) {
      mergeAssociations(entity.aggregatedAssociations, { malwareFamilies: matchedMalware, actors: matchedActors, campaigns: matchedCampaigns });
      linked += 1;
    }
  }
  return linked;
}

export function isIocExtractionProcessed(articleLink) {
  return state.processedArticleIds.includes(articleLink);
}

export function markIocExtractionProcessed(articleLink) {
  if (!state.processedArticleIds.includes(articleLink)) state.processedArticleIds.push(articleLink);
}

export function findIndicator(type, value) {
  const id = canonicalId(type, normalizeIndicator(type, value));
  return state.entities.find((e) => e.id === id) ?? null;
}

/** Cross-type lookup by bare value -- used by server/investigation/crossReference.js, which doesn't always know the exact fine-grained type up front (e.g. "hash" without knowing sha256 vs sha1 vs md5). */
export function findIndicatorByValue(value) {
  const normalizedLower = (value ?? "").toString().trim().toLowerCase();
  return state.entities.find((e) => e.value.toLowerCase() === normalizedLower) ?? null;
}

export function getAllEntities() {
  return [...state.entities].sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
}

export function getEntityCount() {
  return state.entities.length;
}

export function saveAfterMentions() {
  persist();
}

export { CLASSIFICATIONS };
