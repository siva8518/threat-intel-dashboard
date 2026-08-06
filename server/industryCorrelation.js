// Tiered, confidence-scored industry correlation for server/industryBriefing.js.
//
// Why this file exists: the original Industry Intelligence implementation
// only ever showed an actor/malware/campaign if it happened to be named in
// the title of one of the ~50 articles keyword-matched to that industry's own
// pool (see poolForIndustry in industryBriefing.js) -- a narrow, title-only
// signal that left most sectors' Active Threat Actors / Active Campaigns /
// Trending Malware Families cards empty most of the time, even though this
// platform has ~900 actor entities, ~220 campaign entities, and hundreds of
// ransomware victim disclosures sitting right there in its own stores.
//
// Root cause confirmed live: server/threatActorIntelligence.js,
// server/campaignIntelligence.js, and server/darkWebIntelligence.js all tag
// their own entities' targetedIndustries using server/newsCorrelation.js's
// matchIndustries() -- an OLDER, different 4-bucket taxonomy (FSI/TMT/LSHC/
// Consumer, see server/data/industry-map.json) than the 14-sector taxonomy
// this feature uses (server/data/industry-map-14.json, "Financial Services",
// "Healthcare", etc., via server/emergingThreatsRanking.js's OWN, differently
// named matchIndustries()). A direct `entity.targetedIndustries.includes(
// "Financial Services")` check can never succeed -- entity.targetedIndustries
// never contains that exact 14-sector string. This file works around that
// mismatch by recomputing industry relevance at read-time against each
// entity's own real accumulated text (article titles, ATT&CK's own free-text
// targetIndustries, ransomware.live's own sector field) using the 14-sector
// matcher plus a small synonym table for the common single-word labels
// (e.g. ATT&CK's "Banking", ransomware.live's "Finance") that the 14-sector
// keyword list's own multi-word phrases ("financial services") don't catch --
// no data migration, no change to how the entity stores persist.
//
// Every entity surfaced below is real (an actual record in this platform's
// own entity stores) and every tier is honestly labeled with WHY it was
// included -- this deliberately does not invent names the platform has never
// observed. Three tiers, most to least confident:
//   "direct"       -- the entity's own text (articles, ransomware victims,
//                      ATT&CK targeting data) matches this industry.
//   "cross-linked" -- the entity doesn't directly match, but is linked
//                      (actor<->malware<->campaign co-mention, already
//                      computed by each store's own reconcile()) to another
//                      entity that DOES directly match.
//   "historical"   -- a small, curated, widely-published sector-affinity
//                      list (e.g. FIN7 -> Retail/Hospitality) used ONLY to
//                      fill remaining slots when tiers 1-2 are thin, and
//                      ONLY ever surfaces entities this platform already has
//                      a real record for -- never a name invented here.
import { matchIndustries as matchIndustries14 } from "./emergingThreatsRanking.js";
import { getAllEntities as getActorEntities } from "./threatActorIntelligence.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { getAllEntities as getCampaignEntities } from "./campaignIntelligence.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "./ransomwareCampaigns.js";

export function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

function clampConfidence(n) {
  return Math.max(1, Math.min(99, Math.round(n)));
}

// Single-word/short-phrase labels that show up verbatim in ATT&CK's own
// targetIndustries data and ransomware.live's own `activity` field, but
// aren't literally substrings of the 14-sector keyword map's own
// multi-word phrases (server/data/industry-map-14.json requires e.g.
// "financial services", not bare "financial" or "banking" -- though
// "banking"/"bank" happen to already be in that list; this table only adds
// what the phrase list genuinely misses). Deliberately conservative: an
// ambiguous label (ransomware.live's "Consumer", ATT&CK-style "TMT") is left
// unmapped rather than force-guessed into one sector.
const INDUSTRY_SYNONYMS = new Map(
  Object.entries({
    financial: "Financial Services",
    finance: "Financial Services",
    fsi: "Financial Services",
    insurer: "Insurance",
    health: "Healthcare",
    hospital: "Healthcare",
    medical: "Healthcare",
    lshc: "Healthcare",
    biotech: "Pharmaceuticals",
    defense: "Government",
    military: "Government",
    federal: "Government",
    industrial: "Manufacturing",
    automotive: "Manufacturing",
    aerospace: "Manufacturing",
    retail: "Retail",
    ecommerce: "Retail",
    "e-commerce": "Retail",
    technology: "Technology",
    tech: "Technology",
    software: "Technology",
    telecom: "Telecommunications",
    telecommunication: "Telecommunications",
    media: "Media & Entertainment",
    entertainment: "Media & Entertainment",
    energy: "Energy & Utilities",
    utility: "Energy & Utilities",
    utilities: "Energy & Utilities",
    oil: "Energy & Utilities",
    power: "Energy & Utilities",
    education: "Education",
    academic: "Education",
    transportation: "Transportation & Logistics",
    logistics: "Transportation & Logistics",
    shipping: "Transportation & Logistics",
    aviation: "Transportation & Logistics",
    hospitality: "Hospitality",
    hotel: "Hospitality",
    tourism: "Hospitality",
  }),
);

/** Every 14-sector industry a free-text blob (article titles, ATT&CK targetIndustries, ransomware.live sector/victim) real-world matches -- phrase-based keyword match first, then the single-word synonym table above for common short labels the phrase list itself doesn't cover. */
export function industriesFromText(text) {
  const hits = new Set(matchIndustries14(text ?? ""));
  const lower = norm(text);
  for (const [word, industry] of INDUSTRY_SYNONYMS) {
    if (lower.includes(word)) hits.add(industry);
  }
  return [...hits];
}

/** This entity's own real grounding text -- article titles, description, and (for actors) whatever free-text sector labels ATT&CK/ransomware-tracker reconciliation already attached to targetedIndustries -- concatenated for one industriesFromText() pass. */
function entityText(entity) {
  const bits = [
    ...(entity.articles ?? []).map((a) => a.title),
    entity.description ?? "",
    ...(entity.targetedIndustries ?? []),
  ];
  return bits.join(" ");
}

// ---------------------------------------------------------------------------
// Ransomware.live/RansomWatch/RansomLook -- real, high-volume victim
// disclosures (server/ransomwareCampaigns.js), each carrying its own
// upstream sector label (ransomware.live's `activity` field) plus a victim
// org name -- a much richer, more current industry signal than news-title
// keyword matching, and the reason "Active Campaigns"/"Most Active Threat
// Actors" can be populated for virtually every industry, not just the ones
// with a recent dedicated news cycle.
// ---------------------------------------------------------------------------

function ransomwareIndustriesFor(campaign) {
  return industriesFromText(`${campaign.sector ?? ""} ${campaign.victim ?? ""}`);
}

function buildRansomwareIndex() {
  const campaigns = getRansomwareCampaigns();
  const byIndustry = new Map(); // industry -> campaign[]
  for (const c of campaigns) {
    for (const industry of ransomwareIndustriesFor(c)) {
      if (!byIndustry.has(industry)) byIndustry.set(industry, []);
      byIndustry.get(industry).push(c);
    }
  }
  return { campaigns, byIndustry };
}

// ---------------------------------------------------------------------------
// Tier 3 fallback: curated, widely-published actor/malware sector affinities.
// Deliberately small and conservative (only well-documented, broadly-reported
// associations) -- and only ever used to RE-SURFACE a name this platform
// already has a real entity record for (see the `getActorEntities()`/
// `getMalwareEntities()` filter everywhere this is read below), never to
// introduce a name the platform hasn't actually observed.
// ---------------------------------------------------------------------------

const INDUSTRY_ACTOR_AFFINITY = {
  "Financial Services": ["fin7", "fin8", "lazarus group", "lazarus", "carbanak", "cobalt group", "silence", "trickbot", "wizard spider"],
  Insurance: ["scattered spider", "fin7", "cl0p"],
  Healthcare: ["rhysida", "alphv", "blackcat", "conti", "hive", "vice society", "ryuk"],
  Pharmaceuticals: ["apt41", "winnti", "orangeworm"],
  Government: ["apt29", "cozy bear", "apt28", "fancy bear", "sandworm", "apt41", "volt typhoon", "lazarus group", "apt31"],
  Manufacturing: ["lockbit", "blackbyte", "conti", "cl0p", "akira", "black basta"],
  Retail: ["fin7", "fin8", "magecart", "carbanak"],
  Technology: ["lapsus$", "scattered spider", "apt41", "cozy bear"],
  Telecommunications: ["scattered spider", "lightbasin", "volt typhoon", "salt typhoon"],
  "Media & Entertainment": ["lapsus$", "conti"],
  "Energy & Utilities": ["sandworm", "volt typhoon", "xenotime", "electrum", "berserk bear"],
  Education: ["vice society", "lockbit"],
  "Transportation & Logistics": ["black basta", "cl0p"],
  Hospitality: ["fin7", "fin8", "alphv", "blackcat"],
};

const INDUSTRY_MALWARE_AFFINITY = {
  "Financial Services": ["trickbot", "qakbot", "dridex", "zeus", "gozi", "icedid"],
  Insurance: ["blackcat", "cobalt strike"],
  Healthcare: ["ryuk", "conti", "lockbit", "blackcat"],
  Pharmaceuticals: ["winnti"],
  Government: ["sunburst", "cobalt strike"],
  Manufacturing: ["lockbit", "blackbyte", "akira"],
  Retail: ["magecart"],
  Technology: ["cobalt strike", "raccoon stealer"],
  Telecommunications: ["lightbasin"],
  "Media & Entertainment": [],
  "Energy & Utilities": ["industroyer", "triton", "blackenergy"],
  Education: ["lockbit", "vice society"],
  "Transportation & Logistics": ["black basta"],
  Hospitality: ["alphv", "blackcat"],
};

/** Real entity record matching a normalized name/alias, or null -- never a fabricated stand-in. */
function findEntityByName(entities, name) {
  const target = norm(name);
  return entities.find((e) => norm(e.name) === target || (e.aliases ?? []).some((a) => norm(a) === target)) ?? null;
}

// ---------------------------------------------------------------------------
// Threat actors
// ---------------------------------------------------------------------------

/**
 * Tiered, confidence-scored threat-actor list for one industry -- ranks
 * every real actor entity plus every real ransomware group active against
 * this sector, cross-links entities connected to a direct hit, then fills
 * any remaining slots from the curated historical-affinity list (still only
 * ever surfacing a real platform entity). Every result carries {tier,
 * confidenceScore, reason}.
 */
export function rankActorsForIndustry(industry, { limit = 12 } = {}) {
  const actorEntities = getActorEntities();
  const { byIndustry: ransomwareByIndustry } = buildRansomwareIndex();
  const ransomwareHits = ransomwareByIndustry.get(industry) ?? [];
  const ransomwareByGroupId = new Map(); // normalized group id -> campaign[]
  for (const c of ransomwareHits) {
    const key = norm(c.group);
    if (!ransomwareByGroupId.has(key)) ransomwareByGroupId.set(key, []);
    ransomwareByGroupId.get(key).push(c);
  }

  const results = new Map(); // normalized name -> result

  for (const entity of actorEntities) {
    const newsHits = industriesFromText(entityText(entity)).includes(industry);
    const ransomCampaigns = ransomwareByGroupId.get(entity.id) ?? [];
    if (!newsHits && ransomCampaigns.length === 0) continue;

    const newsEvidence = (entity.articles ?? []).filter((a) => industriesFromText(a.title).includes(industry)).length;
    const evidence = newsEvidence + ransomCampaigns.length;
    const parts = [];
    if (newsEvidence > 0) parts.push(`${newsEvidence} ingested report(s)`);
    if (ransomCampaigns.length > 0) parts.push(`${ransomCampaigns.length} ransomware victim disclosure(s)`);

    results.set(entity.id, {
      entity,
      tier: "direct",
      confidenceScore: clampConfidence(72 + Math.min(evidence, 9) * 3),
      reason: `Directly linked to ${parts.join(" and ")} targeting ${industry}.`,
      evidence,
    });
  }

  // Ransomware groups with real victim disclosures in this industry but no
  // matching entity in threatActorIntelligence.js at all (most ransomware
  // brand names are never independently extracted as a news actor mention
  // and aren't in MITRE ATT&CK's own Groups list -- ATT&CK doesn't catalog
  // most ransomware-as-a-service brands) -- still real, evidence-backed
  // activity, so it's synthesized directly from the campaign data rather
  // than being invisible just because no separate actor record exists yet.
  for (const [groupId, campaigns] of ransomwareByGroupId) {
    if (results.has(groupId)) continue;
    const lastSeen = campaigns.reduce((max, c) => (c.discoveredDate > max ? c.discoveredDate : max), campaigns[0].discoveredDate);
    const firstSeen = campaigns.reduce((min, c) => (c.discoveredDate < min ? c.discoveredDate : min), campaigns[0].discoveredDate);
    const country = campaigns.find((c) => c.country && c.country !== "Unknown")?.country ?? null;
    const syntheticEntity = {
      id: groupId,
      name: campaigns[0].group.replace(/\b\w/g, (c) => c.toUpperCase()),
      aliases: [],
      mentionCount: campaigns.length,
      malwareUsed: [],
      techniqueIds: [],
      motivations: ["Financially motivated"],
      country,
      firstSeen,
      lastSeen,
      articles: [],
    };
    results.set(groupId, {
      entity: syntheticEntity,
      tier: "direct",
      confidenceScore: clampConfidence(72 + Math.min(campaigns.length, 9) * 3),
      reason: `Directly linked to ${campaigns.length} ransomware victim disclosure(s) targeting ${industry}.`,
      evidence: campaigns.length,
    });
  }

  // Cross-linked: actors connected (real malwareUsed co-mention, already
  // computed by threatActorIntelligence.js#reconcile) to a direct-tier
  // malware family for this industry, without being directly matched themselves.
  const directMalwareNames = new Set(
    getMalwareEntities()
      .filter((m) => industriesFromText(entityText(m)).includes(industry))
      .map((m) => norm(m.name)),
  );
  for (const entity of actorEntities) {
    if (results.has(entity.id)) continue;
    const linkedMalware = (entity.malwareUsed ?? []).filter((m) => directMalwareNames.has(norm(m)));
    if (linkedMalware.length === 0) continue;
    results.set(entity.id, {
      entity,
      tier: "cross-linked",
      confidenceScore: clampConfidence(45 + Math.min(linkedMalware.length, 4) * 4),
      reason: `Uses ${linkedMalware.slice(0, 3).join(", ")}, which ${linkedMalware.length > 1 ? "are" : "is"} directly tied to ${industry} activity.`,
      evidence: 0,
    });
  }

  // Historical fallback -- only fills remaining slots, only real entities.
  if (results.size < limit) {
    for (const name of INDUSTRY_ACTOR_AFFINITY[industry] ?? []) {
      if (results.size >= limit) break;
      const entity = findEntityByName(actorEntities, name);
      if (!entity || results.has(entity.id)) continue;
      results.set(entity.id, {
        entity,
        tier: "historical",
        confidenceScore: 28,
        reason: `Historically associated with attacks against the ${industry} sector (not tied to a specific report in this platform's current corpus).`,
        evidence: 0,
      });
    }
  }

  return [...results.values()]
    .sort((a, b) => b.confidenceScore - a.confidenceScore || b.entity.mentionCount - a.entity.mentionCount)
    .slice(0, limit);
}

// ---------------------------------------------------------------------------
// Malware families
// ---------------------------------------------------------------------------

/** Tiered, confidence-scored malware-family list -- same direct/cross-linked/historical structure as rankActorsForIndustry, cross-linked here means "used by a direct-tier actor for this industry." */
export function rankMalwareForIndustry(industry, actorResults, { limit = 12 } = {}) {
  const malwareEntities = getMalwareEntities();
  const results = new Map();

  for (const entity of malwareEntities) {
    const evidence = (entity.articles ?? []).filter((a) => industriesFromText(a.title).includes(industry)).length;
    if (evidence === 0 && !industriesFromText(entityText(entity)).includes(industry)) continue;
    results.set(entity.id, {
      entity,
      tier: "direct",
      confidenceScore: clampConfidence(72 + Math.min(evidence, 9) * 3),
      reason: `Directly linked to ${Math.max(evidence, 1)} ingested report(s) covering ${industry}.`,
      evidence,
    });
  }

  for (const actorResult of actorResults ?? []) {
    if (actorResult.tier === "historical") continue; // two low-confidence hops stacked is too speculative to show as "cross-linked"
    for (const malwareName of actorResult.entity.malwareUsed ?? []) {
      const entity = findEntityByName(malwareEntities, malwareName);
      if (!entity || results.has(entity.id)) continue;
      results.set(entity.id, {
        entity,
        tier: "cross-linked",
        confidenceScore: clampConfidence((actorResult.tier === "direct" ? 45 : 35) + 8),
        reason: `Used by ${actorResult.entity.name}, an actor ${actorResult.tier === "direct" ? "directly" : "indirectly"} tied to ${industry} activity.`,
        evidence: 0,
      });
    }
  }

  if (results.size < limit) {
    for (const name of INDUSTRY_MALWARE_AFFINITY[industry] ?? []) {
      if (results.size >= limit) break;
      const entity = findEntityByName(malwareEntities, name);
      if (!entity || results.has(entity.id)) continue;
      results.set(entity.id, {
        entity,
        tier: "historical",
        confidenceScore: 26,
        reason: `Historically observed in attacks against the ${industry} sector (not tied to a specific report in this platform's current corpus).`,
        evidence: 0,
      });
    }
  }

  return [...results.values()]
    .sort((a, b) => b.confidenceScore - a.confidenceScore || b.entity.mentionCount - a.entity.mentionCount)
    .slice(0, limit);
}

// ---------------------------------------------------------------------------
// Campaigns -- merges real named campaign entities (campaignIntelligence.js)
// with real ransomware-group victim clusters (grouped per group, since a
// ransomware group's ongoing string of disclosed victims against one sector
// IS a real, active campaign in the plain sense, just not one that ever got
// a named-campaign LLM extraction).
// ---------------------------------------------------------------------------

export function rankCampaignsForIndustry(industry, actorResults, malwareResults, { limit = 12 } = {}) {
  const results = [];
  const seen = new Set();

  const { byIndustry: ransomwareByIndustry } = buildRansomwareIndex();
  const byGroup = new Map();
  for (const c of ransomwareByIndustry.get(industry) ?? []) {
    const key = norm(c.group);
    if (!byGroup.has(key)) byGroup.set(key, { group: c.group, victims: [], firstSeen: c.discoveredDate, lastSeen: c.discoveredDate });
    const entry = byGroup.get(key);
    entry.victims.push(c.victim);
    if (new Date(c.discoveredDate) < new Date(entry.firstSeen)) entry.firstSeen = c.discoveredDate;
    if (new Date(c.discoveredDate) > new Date(entry.lastSeen)) entry.lastSeen = c.discoveredDate;
  }
  for (const entry of byGroup.values()) {
    const key = `ransomware:${norm(entry.group)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push({
      name: `${entry.group} ransomware operations`,
      associatedActors: [entry.group],
      associatedMalware: [],
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      verified: true,
      mentionCount: entry.victims.length,
      tier: "direct",
      confidenceScore: clampConfidence(72 + Math.min(entry.victims.length, 9) * 3),
      reason: `${entry.victims.length} real ransomware victim disclosure(s) against ${industry} organizations, most recently ${new Date(entry.lastSeen).toISOString().slice(0, 10)}.`,
    });
  }

  const directActorNames = new Set((actorResults ?? []).filter((a) => a.tier === "direct").map((a) => norm(a.entity.name)));
  const directMalwareNames = new Set((malwareResults ?? []).filter((m) => m.tier === "direct").map((m) => norm(m.entity.name)));

  for (const entity of getCampaignEntities()) {
    const key = `named:${entity.id}`;
    if (seen.has(key)) continue;
    const directHit = industriesFromText(entityText(entity)).includes(industry);
    const linkedActors = (entity.associatedActors ?? []).filter((a) => directActorNames.has(norm(a)));
    const linkedMalware = (entity.associatedMalware ?? []).filter((m) => directMalwareNames.has(norm(m)));
    if (!directHit && linkedActors.length === 0 && linkedMalware.length === 0) continue;
    seen.add(key);

    const tier = directHit ? "direct" : "cross-linked";
    const reasonBits = [];
    if (directHit) reasonBits.push(`its own coverage matches ${industry}`);
    if (linkedActors.length) reasonBits.push(`linked to ${linkedActors.slice(0, 2).join(", ")}`);
    if (linkedMalware.length) reasonBits.push(`uses ${linkedMalware.slice(0, 2).join(", ")}`);

    results.push({
      name: entity.name,
      associatedActors: entity.associatedActors ?? [],
      associatedMalware: entity.associatedMalware ?? [],
      firstSeen: entity.firstSeen ?? null,
      lastSeen: entity.lastSeen ?? null,
      verified: Boolean(entity.verified),
      mentionCount: entity.mentionCount ?? 0,
      tier,
      confidenceScore: clampConfidence(directHit ? 72 + Math.min(entity.mentionCount ?? 0, 9) * 3 : 45 + Math.min(linkedActors.length + linkedMalware.length, 4) * 4),
      reason: `Campaign ${reasonBits.join("; ")}.`,
    });
  }

  return results.sort((a, b) => b.confidenceScore - a.confidenceScore || b.mentionCount - a.mentionCount).slice(0, limit);
}

// ---------------------------------------------------------------------------
// IOC feed broadening -- the original buildIndustryIocFeed only pulled from
// malware entities that were themselves DIRECTLY matched to the industry;
// this also gathers indicators for malware used by a direct-tier actor, so a
// real actor<->malware<->IOC chain still surfaces indicators even when the
// malware family itself had no direct sector text match.
// ---------------------------------------------------------------------------

export function iocEligibleMalwareNames(malwareResults, actorResults) {
  const names = new Set((malwareResults ?? []).map((m) => norm(m.entity.name)));
  for (const actorResult of actorResults ?? []) {
    if (actorResult.tier !== "direct") continue;
    for (const m of actorResult.entity.malwareUsed ?? []) names.add(norm(m));
  }
  return names;
}
