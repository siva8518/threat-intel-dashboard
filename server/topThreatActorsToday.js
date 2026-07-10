// Top Threat Actors Today: a ranked, same-calendar-day activity leaderboard
// -- distinct from server/correlate.js#mergeThreatActors, which is an
// all-time (not "today") ransomware.live + OTX merge and only ever surfaces
// one name (the executive summary's "Most Active Threat Actor"). This
// widens coverage past that in two ways: it combines THREE signals instead
// of two (ransomware.live victim posts, OTX pulse adversary tags, AND
// Security Newsroom's actor tagging -- the same tagging already computed in
// newsCorrelation.js, not a separate re-derivation), and it canonicalizes
// every raw name through MITRE ATT&CK's own alias lists first, so e.g. a
// ransomware.live group and a news mention that both refer to the same real
// actor under different spellings/aliases count as one entry, not two.
//
// Confirmed live while building this: on a quiet day, ransomware.live is by
// far the dominant signal (dozens of victim posts/day vs. sparse OTX/news
// actor mentions) -- so the top of this list will often be ransomware gangs
// with occasional APT/crimeware names mixed in whenever OTX or news actually
// covers one that day. That's an honest reflection of what these free
// sources actually cover in bulk, not a bug: there's no free source that
// reports daily APT activity volume the way ransomware.live does for
// ransomware.
import { isToday } from "./todaySecurityEvents.js";
import { recordAndGetPriorActorSnapshot } from "./actorTrendHistory.js";

const TOP_N = 5;

function normalize(name) {
  return (name ?? "").toLowerCase().replace(/\s+/g, "");
}

/** normalized alias -> canonical ATT&CK group name. */
function buildAliasMap(attackData) {
  const map = new Map();
  for (const g of attackData?.groups ?? []) {
    for (const alias of [g.name, ...(g.aliases ?? [])]) {
      map.set(normalize(alias), g.name);
    }
  }
  return map;
}

export function buildTopThreatActorsToday({ ransomwareCampaigns, otxActorSignals, newsItems, attackData }) {
  const aliasMap = buildAliasMap(attackData);
  const scores = new Map(); // normalized canonical name -> score
  const displayNames = new Map(); // normalized canonical name -> display casing (first one seen)

  function addScore(rawName) {
    if (!rawName) return;
    const canonical = aliasMap.get(normalize(rawName)) ?? rawName; // no ATT&CK match (e.g. a pure ransomware brand) -- use the raw name as-is
    const key = normalize(canonical);
    scores.set(key, (scores.get(key) ?? 0) + 1);
    if (!displayNames.has(key)) displayNames.set(key, canonical);
  }

  for (const c of ransomwareCampaigns ?? []) {
    if (isToday(c.discoveredDate)) addScore(c.group);
  }
  for (const s of otxActorSignals ?? []) {
    if (isToday(s.date)) addScore(s.name);
  }
  for (const item of newsItems ?? []) {
    if (!isToday(item.publishedDate)) continue;
    for (const actor of item.tags?.actors ?? []) addScore(actor);
  }

  const ranked = [...scores.entries()]
    .map(([key, score]) => ({ key, name: displayNames.get(key), score }))
    .sort((a, b) => b.score - a.score)
    .slice(0, TOP_N);

  // Always records today's full scoreboard (idempotent per day) so there's a
  // baseline for tomorrow's comparison, even for actors outside today's top N.
  const scoreSnapshot = Object.fromEntries(scores.entries());
  const prior = recordAndGetPriorActorSnapshot(scoreSnapshot);

  return ranked.map((entry, i) => {
    const priorScore = prior?.actors?.[entry.key] ?? 0;
    const trend = priorScore === 0 || entry.score > priorScore ? "up" : entry.score < priorScore ? "down" : "steady";
    return { rank: i + 1, name: entry.name, score: entry.score, trend };
  });
}
