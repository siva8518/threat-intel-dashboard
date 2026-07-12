// Canonical threat-actor entity store -- the "one record per actor" backbone
// for the Threat Actor Intelligence page and the RAG chatbot, mirroring
// server/malwareIntelligence.js exactly. Every actor name ever extracted from
// news (server/threatActorExtraction.js) or already catalogued in MITRE
// ATT&CK's Groups list gets exactly one record here, persisted to disk,
// enriched over time, and never silently dropped. reconcile() seeds one
// entity per ATT&CK group up front (see seedFromAttack below), so this store
// is always a strict superset of what the old ATT&CK-only actor chunk source
// showed -- a brand-new group named by a vendor blog before it ever gets an
// ATT&CK entry still gets its own record the same way "Bumblebee" did for
// malware.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { industryForSector } from "./correlate.js";
import { matchCveIds, matchIndustries, matchCountries } from "./newsCorrelation.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "threat-actor-intelligence.json");
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
export function normalizeActorId(name) {
  return name.trim().toLowerCase().replace(/\s+/g, " ");
}

export function isArticleProcessed(articleId) {
  return state.processedArticleIds.includes(articleId);
}

export function markArticleProcessed(articleId) {
  if (!state.processedArticleIds.includes(articleId)) state.processedArticleIds.push(articleId);
}

function emptyEntity(id, name, type, article) {
  return {
    id,
    name: name.trim(),
    aliases: [],
    type,
    description: null,
    attackId: null,
    attackUrl: null,
    country: null,
    motivations: [],
    activeSince: null,
    verified: false,
    malwareUsed: [],
    targetedIndustries: [],
    targetedCountries: [],
    cveExploited: [],
    techniqueIds: [],
    firstSeen: article.publishedDate,
    lastSeen: article.publishedDate,
    mentionCount: 0,
    articles: [],
  };
}

function mergeUnique(existing, incoming) {
  const set = new Set(existing);
  for (const item of incoming) set.add(item);
  return Array.from(set);
}

/**
 * Records one actor mention from one article -- creates a new record or
 * merges into the existing one for that name, same "exactly one record per
 * name" guarantee as server/malwareIntelligence.js#upsertMention. Also
 * derives targetedIndustries/targetedCountries/cveExploited directly from
 * this article's own text (the same substring-matching primitives
 * server/newsCorrelation.js already uses for news tagging), so an actor's
 * profile accumulates real signal from every article it's mentioned in
 * without needing a second pass.
 */
export function upsertMention(rawName, type, article) {
  const id = normalizeActorId(rawName);
  let entity = state.entities.find((e) => e.id === id);
  const isNew = !entity;

  if (!entity) {
    entity = emptyEntity(id, rawName, type, article);
    state.entities.push(entity);
  } else if (entity.type === "Unknown" && type !== "Unknown") {
    entity.type = type; // first confident classification wins; don't flip-flop on later disagreement
  }

  if (rawName.trim() !== entity.name && !entity.aliases.includes(rawName.trim())) {
    entity.aliases.push(rawName.trim());
  }

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
 * ATT&CK motivation keywords -> our type taxonomy, used only to refine an
 * "Unknown" classification once ATT&CK confirms the group. Also scans the
 * group's own free-text description, not just its (often empty) structured
 * `motivations` field -- confirmed live that ATT&CK's own regex-extracted
 * motivations is empty for well-known groups like APT29 and FIN7 even though
 * their descriptions plainly say "financially-motivated" or "Foreign
 * Intelligence Service", so relying on `motivations` alone left textbook
 * cases classified "Unknown".
 */
function typeFromMotivations(motivations, description) {
  const lower = [...(motivations ?? []).map((m) => m.toLowerCase()), (description ?? "").toLowerCase()];
  const has = (...keywords) => lower.some((text) => keywords.some((k) => text.includes(k)));
  // "financially motivated"/"cybercrime" is checked before "ransomware" --
  // confirmed live that a group like FIN7 (fundamentally a financially-
  // motivated crime group that later added a ransomware-as-a-service line of
  // business) has "ransomware" appear incidentally in its description, which
  // otherwise misclassified it as a pure ransomware operation. A pure
  // ransomware-native group not in ATT&CK at all still gets typed correctly
  // via the stronger, direct ransomware-tracker match in reconcile() below,
  // which overrides this heuristic guess regardless of order.
  if (has("financially motivated", "financially-motivated", "cybercrime")) return "Cybercrime";
  if (has("ransomware")) return "Ransomware";
  if (has("hacktivis")) return "Hacktivist";
  if (has("initial access broker", "access broker")) return "Initial Access Broker";
  if (has("insider threat")) return "Insider";
  if (has("espionage", "intelligence service", "intelligence agency", "nation-state", "state-sponsored", "military unit")) return "APT";
  return null;
}

/**
 * Seeds one entity per ATT&CK group that doesn't already have a record --
 * this is what makes the store a strict superset of the old plain
 * actorChunks() (server/rag/chunkBuilder.js), not a narrower replacement of
 * it. Mirrors server/malwareIntelligence.js#reconcile's IOC-family seeding.
 */
function seedFromAttack(attackData) {
  const existingIds = new Set(state.entities.map((e) => e.id));
  const softwareById = new Map((attackData?.software ?? []).map((s) => [s.id, s]));
  for (const g of attackData?.groups ?? []) {
    const id = normalizeActorId(g.name);
    if (existingIds.has(id)) continue;
    const now = new Date().toISOString();
    state.entities.push({
      id,
      name: g.name,
      aliases: [...(g.aliases ?? [])],
      type: typeFromMotivations(g.motivations, g.description) ?? "Unknown",
      description: g.description ?? null,
      attackId: g.attackId,
      attackUrl: g.url ?? null,
      country: g.country ?? null,
      motivations: g.motivations ?? [],
      activeSince: g.activeSince ?? null,
      verified: true,
      malwareUsed: (g.softwareIds ?? []).map((sid) => softwareById.get(sid)?.name).filter(Boolean),
      targetedIndustries: g.targetIndustries ?? [],
      targetedCountries: [],
      cveExploited: g.cveIds ?? [],
      techniqueIds: g.techniqueIds ?? [],
      firstSeen: now,
      lastSeen: now,
      mentionCount: 0,
      articles: [],
    });
    existingIds.add(id);
  }
}

/**
 * Enriches every record against MITRE ATT&CK's Groups list (real
 * description/country/motivations/techniques/software, a stable id) and
 * ransomware tracker data (a strong "this is a ransomware operation" signal
 * plus real victim country/sector), then cross-references
 * server/malwareIntelligence.js's own entity store for malware<->actor
 * co-mentions: if a malware family and this actor were both named in the
 * same article, that family is added to `malwareUsed` -- the mechanism
 * behind "Show actors using Bumblebee" without needing joint extraction.
 */
export function reconcile(attackData, ransomwareCampaigns) {
  seedFromAttack(attackData);

  const groupsByNameLower = new Map();
  for (const g of attackData?.groups ?? []) {
    for (const n of [g.name, ...(g.aliases ?? [])]) groupsByNameLower.set(n.toLowerCase(), g);
  }
  const softwareById = new Map((attackData?.software ?? []).map((s) => [s.id, s]));

  for (const entity of state.entities) {
    const candidates = [entity.name, ...entity.aliases].map((n) => n.toLowerCase());
    const match = candidates.map((n) => groupsByNameLower.get(n)).find(Boolean);
    if (match && !entity.attackId) {
      entity.attackId = match.attackId;
      entity.attackUrl = match.url ?? null;
      entity.description = match.description || entity.description;
      entity.name = match.name; // prefer ATT&CK's official casing once confirmed
      entity.country = match.country ?? entity.country;
      entity.motivations = match.motivations?.length ? match.motivations : entity.motivations;
      entity.activeSince = match.activeSince ?? entity.activeSince;
      entity.techniqueIds = mergeUnique(entity.techniqueIds, match.techniqueIds ?? []);
      entity.targetedIndustries = mergeUnique(entity.targetedIndustries, match.targetIndustries ?? []);
      entity.malwareUsed = mergeUnique(
        entity.malwareUsed,
        (match.softwareIds ?? []).map((sid) => softwareById.get(sid)?.name).filter(Boolean),
      );
      entity.verified = true;
      if (entity.type === "Unknown") entity.type = typeFromMotivations(match.motivations, match.description) ?? "Unknown";
      for (const alias of match.aliases ?? []) if (!entity.aliases.includes(alias)) entity.aliases.push(alias);
    }

    const campaignHit = (ransomwareCampaigns ?? []).find((c) => c.group?.toLowerCase() === entity.id || entity.aliases.some((a) => a.toLowerCase() === c.group?.toLowerCase()));
    if (campaignHit) {
      entity.type = "Ransomware"; // strong, direct signal -- overrides a weaker/unknown guess
      entity.verified = true;
      if (campaignHit.sector) entity.targetedIndustries = mergeUnique(entity.targetedIndustries, [industryForSector(campaignHit.sector)]);
      if (campaignHit.country) entity.targetedCountries = mergeUnique(entity.targetedCountries, [campaignHit.country]);
    }

    // Malware<->actor co-mention: same article named both.
    const ownArticleLinks = new Set(entity.articles.map((a) => a.link));
    if (ownArticleLinks.size > 0) {
      for (const malware of getMalwareEntities()) {
        if (malware.articles.some((a) => ownArticleLinks.has(a.link))) {
          entity.malwareUsed = mergeUnique(entity.malwareUsed, [malware.name]);
        }
      }
    }
  }

  // Merge duplicate records that reconcile() just confirmed share one ATT&CK
  // group id (e.g. two spellings extracted before either was matched).
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
    existing.malwareUsed = mergeUnique(existing.malwareUsed, entity.malwareUsed);
    existing.targetedIndustries = mergeUnique(existing.targetedIndustries, entity.targetedIndustries);
    existing.targetedCountries = mergeUnique(existing.targetedCountries, entity.targetedCountries);
    existing.cveExploited = mergeUnique(existing.cveExploited, entity.cveExploited);
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
