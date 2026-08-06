// Canonical alias resolution -- a search for "Cozy Bear" or "Midnight
// Blizzard" should land on the same investigation as "APT29", and "Qbot"
// should land on the same one as "QakBot". crossReference.js#searchEntitiesByName
// and investigationGraph.js#findByNameOrAlias already match against
// whatever aliases happen to already be sitting in an entity's own stored
// `aliases[]` array (populated opportunistically during ATT&CK sync / news
// extraction) -- this file adds a small, curated supplemental table for
// extremely well-documented multi-name cases that extraction may not have
// linked yet, PLUS a single shared resolver both index.js and
// investigationGraph.js call before dispatch, so an alias search resolves to
// the canonical entity consistently everywhere, not just wherever a
// substring match happens to fire.
//
// Deliberately small and conservative -- same discipline as
// server/industryCorrelation.js's INDUSTRY_ACTOR_AFFINITY: this table is a
// HINT that two strings name the same real-world thing, never a source of
// truth for whether that thing exists in this platform. resolveCanonicalAlias()
// below only ever returns a name when a REAL entity for it already exists in
// one of this app's own three entity stores -- it never fabricates one, and
// it deliberately does NOT use fuzzy/edit-distance matching (see
// server/malwareIntelligence.js's own comment on why: "too easy to wrongly
// merge two unrelated short names"). This also avoids any new dependency on
// local embeddings/Ollama for what is, for every example below, a
// well-documented EXACT alias, not a fuzzy near-miss.
import { getAllEntities as getActorEntities } from "../threatActorIntelligence.js";
import { getAllEntities as getMalwareEntities } from "../malwareIntelligence.js";
import { getAllEntities as getCampaignEntities } from "../campaignIntelligence.js";
import { findByNameOrAlias, norm } from "./entityLookup.js";

const KNOWN_ALIAS_GROUPS = [
  { canonical: "APT29", aliases: ["Cozy Bear", "Midnight Blizzard", "Nobelium", "The Dukes", "Iron Hemlock"] },
  { canonical: "APT28", aliases: ["Fancy Bear", "Forest Blizzard", "Sofacy", "Sednit", "STRONTIUM"] },
  { canonical: "Sandworm Team", aliases: ["Sandworm", "Seashell Blizzard", "Voodoo Bear", "APT44", "Iridium"] },
  { canonical: "Lazarus Group", aliases: ["Lazarus", "Hidden Cobra", "APT38", "Zinc", "Diamond Sleet"] },
  { canonical: "FIN7", aliases: ["Carbon Spider", "Sangria Tempest"] },
  { canonical: "Volt Typhoon", aliases: ["Bronze Silhouette", "Vanguard Panda"] },
  { canonical: "Scattered Spider", aliases: ["UNC3944", "Octo Tempest", "Star Fraud", "Muddled Libra"] },
  { canonical: "Wizard Spider", aliases: ["Conti", "TrickBot Gang"] },
  { canonical: "ALPHV", aliases: ["BlackCat", "Noberus"] },
  { canonical: "QakBot", aliases: ["Qbot", "Pinkslipbot", "Quakbot"] },
  { canonical: "TrickBot", aliases: ["Trickster", "TrickLoader"] },
  { canonical: "Emotet", aliases: ["Geodo", "Heodo"] },
  { canonical: "IcedID", aliases: ["BokBot"] },
  { canonical: "Agent Tesla", aliases: ["AgentTesla"] },
];

function buildAliasIndex() {
  const index = new Map();
  for (const group of KNOWN_ALIAS_GROUPS) {
    index.set(norm(group.canonical), group.canonical);
    for (const alias of group.aliases) index.set(norm(alias), group.canonical);
  }
  return index;
}
const ALIAS_INDEX = buildAliasIndex();

/**
 * Resolves `value` to the canonical name of a REAL entity already tracked in
 * this platform's actor/malware/campaign stores. Checks the curated table
 * above first, then falls back to any alias this platform already extracted
 * into an entity's own `aliases[]` (e.g. an ATT&CK-sourced alias not in the
 * curated table). Returns null when `value` already IS the canonical form,
 * when nothing resolves, or when the curated table's "canonical" side isn't
 * itself a real stored entity (never fabricates one).
 */
export function resolveCanonicalAlias(value) {
  const target = norm(value);
  const allEntities = () => [...getActorEntities(), ...getMalwareEntities(), ...getCampaignEntities()];

  const curated = ALIAS_INDEX.get(target);
  if (curated && norm(curated) !== target && findByNameOrAlias(allEntities(), curated)) {
    return curated;
  }

  const actor = findByNameOrAlias(getActorEntities(), value);
  if (actor && norm(actor.name) !== target) return actor.name;
  const malware = findByNameOrAlias(getMalwareEntities(), value);
  if (malware && norm(malware.name) !== target) return malware.name;
  const campaign = findByNameOrAlias(getCampaignEntities(), value);
  if (campaign && norm(campaign.name) !== target) return campaign.name;

  return null;
}
