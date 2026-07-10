// Shared, deduped ransomware-campaign builder -- same pattern as
// threatFeed.js. Merges ransomware.live (richest: has sector/country) with
// RansomWatch and RansomLook (thinner: group/victim/date only), since the
// same leak-site post often gets picked up by more than one tracker.
// Factored into one module so every route/feature that needs "ransomware
// campaigns" (the dashboard routes, Threat Actor Profiles) reads the exact
// same merged list, not three separate raw sources.
import * as cache from "./cache.js";

const SOURCE_IDS = ["ransomware-live", "ransomwatch", "ransomlook"];

// Confirmed live: the same real-world post shows up with the group name
// spaced differently across trackers -- e.g. ransomware.live's
// "moneymessage" vs. RansomLook's "money message" for the same victim.
// Stripping whitespace (not just lowercasing) keeps these as one merged
// campaign instead of two duplicate entries racing each other on recency,
// and lets the group-page fallback below match ransomware.live's own
// "thegentlemen"-style group directory names.
function normalizeGroup(g) {
  return (g ?? "").toLowerCase().replace(/\s+/g, "");
}

function dedupeKey(campaign) {
  return `${normalizeGroup(campaign.group)}|${(campaign.victim ?? "").toLowerCase()}`;
}

export function ransomwareCampaigns() {
  const all = SOURCE_IDS.flatMap((id) => cache.getEntry(id).data ?? []);
  const byKey = new Map();

  for (const campaign of all) {
    const key = dedupeKey(campaign);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...campaign });
      continue;
    }
    // Prefer real sector/country data over "Unknown", keep the earliest discovery date, keep any real source link.
    if (existing.sector === "Unknown" && campaign.sector !== "Unknown") existing.sector = campaign.sector;
    if (existing.country === "Unknown" && campaign.country !== "Unknown") existing.country = campaign.country;
    if (new Date(campaign.discoveredDate) < new Date(existing.discoveredDate)) existing.discoveredDate = campaign.discoveredDate;
    if (!existing.sourceUrl && campaign.sourceUrl) existing.sourceUrl = campaign.sourceUrl;
  }

  // Confirmed live: a large share of victim posts (especially fresh
  // RansomLook-only entries not yet mirrored by ransomware.live's own
  // per-victim feed) have no direct sourceUrl at all -- otherwise
  // unclickable. Fall back to the group's own profile page from
  // server/connectors/ransomwareGroups.js, a real link (not fabricated),
  // just less specific than a per-victim page.
  const groupPages = cache.getEntry("ransomware-groups").data ?? [];
  const groupUrlByName = new Map(groupPages.map((g) => [normalizeGroup(g.name), g.url]));
  for (const campaign of byKey.values()) {
    if (!campaign.sourceUrl) {
      campaign.sourceUrl = groupUrlByName.get(normalizeGroup(campaign.group)) ?? null;
    }
  }

  return Array.from(byKey.values()).sort((a, b) => new Date(b.discoveredDate).getTime() - new Date(a.discoveredDate).getTime());
}
