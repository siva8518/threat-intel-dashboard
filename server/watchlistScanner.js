// Scans every intelligence source this platform already syncs -- news,
// malware/actor/campaign/dark-web intelligence, ransomware leak-site victim
// posts -- for mentions of any name on the user's watchlist (see
// server/watchlist.js), and records a flash report the first time each
// keyword<->source pair is seen. No new data is fetched here, same
// "everything comes from what's already synced" discipline as
// server/rag/chunkBuilder.js -- this only reads server/cache.js and the
// existing entity stores.
import * as cache from "./cache.js";
import { getAllEntities as getMalwareEntities } from "./malwareIntelligence.js";
import { getAllEntities as getActorEntities } from "./threatActorIntelligence.js";
import { getAllEntities as getCampaignEntities } from "./campaignIntelligence.js";
import { getAllEntities as getDarkWebEntities } from "./darkWebIntelligence.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "./ransomwareCampaigns.js";
import { getKeywords, keywordMatches, recordMatchIfNew, saveAfterScan } from "./watchlist.js";
import { log } from "./lib/log.js";

const SCAN_INTERVAL_MS = 3 * 60 * 1000;

function scanNews(keyword) {
  const items = cache.getEntry("news").data?.items ?? [];
  let found = 0;
  for (const item of items) {
    if (!keywordMatches(keyword, [item.title, item.summary ?? ""])) continue;
    if (
      recordMatchIfNew(keyword, {
        sourceType: "news",
        sourceId: item.link,
        sourceLabel: item.source,
        title: item.title,
        url: item.link,
        snippet: item.summary ?? null,
        foundAt: item.publishedDate,
      })
    ) {
      found += 1;
    }
  }
  return found;
}

/**
 * Checks one entity-store type (malware/actor/campaign/dark-web
 * intelligence). Two independent checks: the entity's own identity fields
 * (name/aliases/description, plus dark-web's victimOrg/platform), and each
 * linked article's own headline -- an entity's name won't mention the
 * client, but one of the articles citing it might (e.g. a vendor's writeup
 * on a malware family that happens to also name a victim in its headline).
 */
function scanEntityStore(keyword, entities, sourceType) {
  let found = 0;
  for (const entity of entities) {
    const ownTexts = [entity.name, ...(entity.aliases ?? []), entity.description ?? "", entity.victimOrg ?? "", entity.platform ?? ""];
    if (keywordMatches(keyword, ownTexts)) {
      if (
        recordMatchIfNew(keyword, {
          sourceType,
          sourceId: entity.id,
          sourceLabel: entity.name,
          title: entity.name,
          url: entity.articles?.[0]?.link ?? entity.attackUrl ?? null,
          snippet: entity.description ?? null,
          foundAt: entity.lastSeen,
        })
      ) {
        found += 1;
      }
    }

    for (const article of entity.articles ?? []) {
      if (!keywordMatches(keyword, [article.title])) continue;
      if (
        recordMatchIfNew(keyword, {
          sourceType,
          sourceId: article.link,
          sourceLabel: `${entity.name} · ${article.source}`,
          title: article.title,
          url: article.link,
          snippet: null,
          foundAt: article.publishedDate,
        })
      ) {
        found += 1;
      }
    }
  }
  return found;
}

function scanRansomware(keyword) {
  let found = 0;
  for (const c of getRansomwareCampaigns()) {
    if (!keywordMatches(keyword, [c.victim])) continue;
    if (
      recordMatchIfNew(keyword, {
        sourceType: "ransomware",
        sourceId: `${c.group}|${c.victim}`,
        sourceLabel: c.group,
        title: `${c.victim} — posted by ${c.group}`,
        url: c.sourceUrl,
        snippet: c.sector && c.sector !== "Unknown" ? `Sector: ${c.sector}` : null,
        foundAt: c.discoveredDate,
      })
    ) {
      found += 1;
    }
  }
  return found;
}

function runScan() {
  const keywords = getKeywords();
  if (keywords.length === 0) return;

  let totalFound = 0;
  for (const keyword of keywords) {
    totalFound += scanNews(keyword);
    totalFound += scanEntityStore(keyword, getMalwareEntities(), "malware");
    totalFound += scanEntityStore(keyword, getActorEntities(), "actor");
    totalFound += scanEntityStore(keyword, getCampaignEntities(), "campaign");
    totalFound += scanEntityStore(keyword, getDarkWebEntities(), "darkweb");
    totalFound += scanRansomware(keyword);
  }

  if (totalFound > 0) {
    saveAfterScan();
    log.info("watchlist-scanner", `found ${totalFound} new flash report(s) across ${keywords.length} tracked name(s)`);
  }
}

export function startWatchlistScannerJob() {
  // Deterministic text matching, not an LLM call -- cheap enough to run
  // early and often, unlike the combined-extraction job's local-model calls.
  setTimeout(runScan, 15_000);
  setInterval(runScan, SCAN_INTERVAL_MS);
}
