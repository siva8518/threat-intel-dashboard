// Daily Summary: a short, skimmable rollup of today's activity, built
// entirely from rule-based counts/comparisons over this app's own live
// data -- no LLM or AI summarization involved (the name used to be "AI
// Daily Brief," which was misleading about that; renamed for accuracy).
// Distinct from Top Security Events Today's raw counts (see
// server/todaySecurityEvents.js), which this reuses/extends rather than
// re-deriving. The KEV line reuses that module's own count directly (so the
// KEV number only ever appears once across the merged Overview tile -- as
// text here, not as its own separate stat tile); ransomware and ThreatFox
// lines compute a different, complementary cut of the same underlying data
// (distinct groups active today, not raw victim-post count; a single
// source's share of "New IOCs," not the aggregate). The malware trend line
// is the one line in this whole app that needs a real day-over-day
// comparison, powered by server/malwareTrendHistory.js.
//
// Each bullet carries an `action` alongside its text so the frontend can
// make it clickable without parsing the sentence back apart -- a tab jump,
// a malware family (opens the same detail drawer used everywhere else), or
// a news source (deep-links into Security Newsroom's existing source filter).
import { isToday } from "./todaySecurityEvents.js";
import { recordAndGetPriorSnapshot } from "./malwareTrendHistory.js";
import { MAJOR_VENDOR_SOURCES } from "./connectors/newsFeeds.js";

function countTodayRansomwareGroups(ransomwareCampaigns) {
  const groups = new Set(
    (ransomwareCampaigns ?? [])
      .filter((c) => isToday(c.discoveredDate))
      .map((c) => (c.group ?? "").toLowerCase().replace(/\s+/g, "")),
  );
  return groups.size;
}

function countTodaySourceIocs(threatFeedIocs, source) {
  return (threatFeedIocs ?? []).filter((i) => i.source === source && isToday(i.firstSeen)).length;
}

function buildMalwareTrendBullet(trendingMalware) {
  const top = trendingMalware?.[0];
  if (!top) return null;

  // Always records today's snapshot (idempotent per day) so there's a
  // baseline for tomorrow's comparison, even when there's no prior snapshot
  // to compare against yet today.
  const prior = recordAndGetPriorSnapshot(trendingMalware);
  const priorCount = prior?.families?.[top.family];

  const action = { type: "malware", family: top.family };

  if (!priorCount) {
    // Honest fallback: no real prior-day baseline yet (fresh deploy, or this
    // family is newly trending) -- state the count, don't invent a trend.
    return { text: `${top.family} is today's most active malware family (${top.count} sighting${top.count === 1 ? "" : "s"})`, action };
  }

  const pctChange = Math.round(((top.count - priorCount) / priorCount) * 100);
  if (pctChange === 0) return { text: `${top.family} activity is steady at ${top.count} sightings, unchanged from yesterday`, action };
  const direction = pctChange > 0 ? "increased" : "decreased";
  return { text: `${top.family} activity ${direction} ${Math.abs(pctChange)}% since yesterday`, action };
}

/**
 * A plain highest-volume-source pick was dominated almost every day by
 * SANS ISC's frequent daily podcast/stormcast posts -- real, but not
 * particularly newsworthy as "today's" highlight. Prefers a real vendor
 * report (Cisco Talos, Microsoft Security, etc. -- see
 * server/connectors/newsFeeds.js#MAJOR_VENDOR_SOURCES) whenever one exists
 * today, and only falls back to the plain highest-volume source (SANS ISC
 * or otherwise) when no major vendor published anything today.
 */
function buildTopNewsSourceBullet(newsItems) {
  const counts = new Map();
  for (const item of newsItems ?? []) {
    if (!isToday(item.publishedDate)) continue;
    counts.set(item.source, (counts.get(item.source) ?? 0) + 1);
  }

  const bySourceDesc = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const topVendor = bySourceDesc.find(([source]) => MAJOR_VENDOR_SOURCES.has(source));
  const top = topVendor ?? bySourceDesc[0];
  if (!top) return null;

  const [source, count] = top;
  return { text: `${source} published ${count} report${count === 1 ? "" : "s"} today`, action: { type: "news-source", source } };
}

const WORDS_PER_MINUTE = 200;

export function buildDailySummary({ todayEvents, ransomwareCampaigns, threatFeedIocs, newsItems, trendingMalware }) {
  const bullets = [];

  bullets.push({
    text: `${todayEvents.criticalKev} new KEV${todayEvents.criticalKev === 1 ? "" : "s"} added to CISA's catalog`,
    action: { type: "tab", tab: "cves" },
  });

  const ransomwareGroupsToday = countTodayRansomwareGroups(ransomwareCampaigns);
  bullets.push({
    text: `${ransomwareGroupsToday} ransomware group${ransomwareGroupsToday === 1 ? "" : "s"} posted new victims`,
    action: { type: "tab", tab: "threat-actors" },
  });

  const threatFoxToday = countTodaySourceIocs(threatFeedIocs, "ThreatFox");
  bullets.push({
    text: `${threatFoxToday} new ThreatFox IOC${threatFoxToday === 1 ? "" : "s"} detected`,
    action: { type: "tab", tab: "malware-intelligence" },
  });

  const malwareBullet = buildMalwareTrendBullet(trendingMalware);
  if (malwareBullet) bullets.push(malwareBullet);

  const newsBullet = buildTopNewsSourceBullet(newsItems);
  if (newsBullet) bullets.push(newsBullet);

  const wordCount = bullets
    .map((b) => b.text)
    .join(" ")
    .split(/\s+/)
    .filter(Boolean).length;
  const readingTimeSeconds = Math.max(10, Math.round(((wordCount / WORDS_PER_MINUTE) * 60) / 5) * 5);

  return { bullets, readingTimeSeconds, generatedAt: new Date().toISOString() };
}
