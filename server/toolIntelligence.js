// Canonical malicious-tool entity store -- the "one record per tool"
// backbone for the Malware Intelligence page's Tools sub-tab and the RAG
// chatbot, mirroring server/malwareIntelligence.js exactly. Every tool name
// ever extracted from news (server/toolExtraction.js) or already catalogued
// in MITRE ATT&CK's Software list under type "tool" gets exactly one record
// here, persisted to disk, enriched over time, and never silently dropped.
//
// TOOLS are distinct from MALWARE: ATT&CK itself classifies each Software
// entry as either "malware" (purpose-built malicious code) or "tool"
// (legitimate/dual-use software -- remote access clients, C2 frameworks,
// red-team/pentest utilities, built-in admin binaries -- reported as used or
// abused by a threat actor). reconcile() below only ever matches against the
// "tool"-typed half of that catalog, so a real malware family can never be
// misclassified into this store even if both stores happen to extract the
// same headline.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "tool-intelligence.json");
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

/** Stable id for dedup -- lowercase, whitespace-collapsed, exact-match only (same policy as server/malwareIntelligence.js#normalizeMalwareId). */
export function normalizeToolId(name) {
  return name.trim().toLowerCase().replace(/\s+/g, " ");
}

export function isArticleProcessed(articleId) {
  return state.processedArticleIds.includes(articleId);
}

export function markArticleProcessed(articleId) {
  if (!state.processedArticleIds.includes(articleId)) state.processedArticleIds.push(articleId);
}

/**
 * Records one tool-name mention from one article. Creates a new record
 * (unverified until reconcile() confirms it against ATT&CK's "tool"-typed
 * Software list) or merges into the existing one for that name.
 */
export function upsertMention(rawName, article) {
  const id = normalizeToolId(rawName);
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
      usedByGroups: [],
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
    entity.articles.unshift({ title: article.title, link: article.link, source: article.source, publishedDate: article.publishedDate });
    entity.articles = entity.articles.slice(0, MAX_ARTICLES_PER_ENTITY);
    entity.mentionCount += 1;
  }

  if (new Date(article.publishedDate) > new Date(entity.lastSeen)) entity.lastSeen = article.publishedDate;
  if (new Date(article.publishedDate) < new Date(entity.firstSeen)) entity.firstSeen = article.publishedDate;

  return { entity, isNew };
}

/**
 * Seeds one entity per ATT&CK Software entry of type "tool" that doesn't
 * already have a record -- this is what makes the store show real content
 * (Mimikatz, Cobalt Strike, PsExec, Impacket, and 100+ others) the moment the
 * app boots, not just whatever news extraction happens to have caught so far.
 * Mirrors server/malwareIntelligence.js#reconcile's IOC-family seeding and
 * server/threatActorIntelligence.js#seedFromAttack.
 */
function seedFromAttack(attackData, usedByGroupsBySoftwareId) {
  const existingIds = new Set(state.entities.map((e) => e.id));
  for (const s of attackData?.software ?? []) {
    if (s.type !== "tool") continue;
    const id = normalizeToolId(s.name);
    if (existingIds.has(id)) continue;
    const now = new Date().toISOString();
    state.entities.push({
      id,
      name: s.name,
      aliases: [...(s.aliases ?? [])],
      description: s.description ?? null,
      attackId: s.attackId,
      attackUrl: s.url ?? null,
      verified: true,
      usedByGroups: usedByGroupsBySoftwareId.get(s.id) ?? [],
      firstSeen: now,
      lastSeen: now,
      mentionCount: 0,
      articles: [],
    });
    existingIds.add(id);
  }
}

/**
 * Enriches every record against MITRE ATT&CK's Software list, restricted to
 * type "tool" only (never "malware" -- that half stays server/
 * malwareIntelligence.js's exclusively) -- real description, official
 * name/aliases, a stable id, and which named ATT&CK groups are recorded as
 * using it.
 */
export function reconcile(attackData) {
  const usedByGroupsBySoftwareId = new Map();
  for (const g of attackData?.groups ?? []) {
    for (const sid of g.softwareIds ?? []) {
      const list = usedByGroupsBySoftwareId.get(sid) ?? [];
      if (!list.includes(g.name)) list.push(g.name);
      usedByGroupsBySoftwareId.set(sid, list);
    }
  }

  seedFromAttack(attackData, usedByGroupsBySoftwareId);

  const toolSoftwareByNameLower = new Map();
  for (const s of attackData?.software ?? []) {
    if (s.type !== "tool") continue;
    for (const n of [s.name, ...(s.aliases ?? [])]) toolSoftwareByNameLower.set(n.toLowerCase(), s);
  }

  for (const entity of state.entities) {
    const candidates = [entity.name, ...entity.aliases].map((n) => n.toLowerCase());
    const match = candidates.map((n) => toolSoftwareByNameLower.get(n)).find(Boolean);
    if (match && !entity.attackId) {
      entity.attackId = match.attackId;
      entity.attackUrl = match.url;
      entity.description = match.description || entity.description;
      entity.name = match.name; // prefer ATT&CK's official casing once confirmed
      entity.verified = true;
      for (const alias of match.aliases ?? []) if (!entity.aliases.includes(alias)) entity.aliases.push(alias);
    }
    if (match) entity.usedByGroups = usedByGroupsBySoftwareId.get(match.id) ?? entity.usedByGroups;
  }

  // Merge duplicate records that reconcile() just confirmed share one ATT&CK
  // software id (e.g. two spellings extracted before either was matched).
  const byAttackId = new Map();
  const merged = [];
  for (const entity of state.entities) {
    if (!entity.attackId) {
      merged.push(entity);
      continue;
    }
    const existing = byAttackId.get(entity.attackId);
    if (!existing) {
      byAttackId.set(entity.attackId, entity);
      merged.push(entity);
      continue;
    }
    for (const a of entity.articles) if (!existing.articles.some((x) => x.link === a.link)) existing.articles.push(a);
    existing.articles.sort((a, b) => new Date(b.publishedDate) - new Date(a.publishedDate));
    existing.articles = existing.articles.slice(0, MAX_ARTICLES_PER_ENTITY);
    existing.mentionCount += entity.mentionCount;
    for (const alias of [entity.name, ...entity.aliases]) if (alias !== existing.name && !existing.aliases.includes(alias)) existing.aliases.push(alias);
    if (new Date(entity.lastSeen) > new Date(existing.lastSeen)) existing.lastSeen = entity.lastSeen;
    if (new Date(entity.firstSeen) < new Date(existing.firstSeen)) existing.firstSeen = entity.firstSeen;
  }
  state.entities = merged;

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
