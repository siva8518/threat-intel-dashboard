// One-time migration: annotates every already-stored threat-actor/campaign
// article with the industries/countries/cves upsertMention() now matches
// from EVERY article (title+summary) at ingest time -- see
// server/threatActorIntelligence.js#recentSignal's own comment for why this
// is needed (recentSignal() would otherwise return empty for all existing
// data until each article happened to be reprocessed, which never happens).
// Title-only best-effort (article.summary isn't persisted on the stored
// record) -- run once via:
//   node scripts/backfillArticleRecency.js
import "dotenv/config";
import { backfillArticleRecency as backfillActors } from "../server/threatActorIntelligence.js";
import { backfillArticleRecency as backfillCampaigns } from "../server/campaignIntelligence.js";

const actorArticles = backfillActors();
const campaignArticles = backfillCampaigns();
console.log(`Backfilled ${actorArticles} threat-actor article(s) and ${campaignArticles} campaign article(s) with industries/countries/cves annotations.`);
