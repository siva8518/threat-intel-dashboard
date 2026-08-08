// One-time migration: recomputes every stored article's/entity's
// `industries` classification using the new unified engine
// (server/industryClassification.js) -- replaces stale values computed
// under the old, retired taxonomies (the 4-bucket LSHC/TMT/FSI/Consumer map
// and the separate, mismatched 14-sector map) with the unified 21-industry
// catalog, and picks up the new technology/vendor signal (the "Atlassian
// Rovo" fix) for data ingested before this change shipped.
//
// Unlike scripts/backfillArticleRecency.js, this FORCE-recomputes every
// entry (does not skip already-annotated ones) -- the whole point here is
// replacing already-present-but-stale values, not filling in gaps. Run once
// via:
//   node scripts/backfillIndustryClassification.js
import "dotenv/config";
import { backfillIndustryClassification as backfillActors } from "../server/threatActorIntelligence.js";
import { backfillIndustryClassification as backfillCampaigns } from "../server/campaignIntelligence.js";
import { backfillIndustryClassification as backfillDarkWeb } from "../server/darkWebIntelligence.js";

const actorArticles = backfillActors();
const campaignArticles = backfillCampaigns();
const darkWebEntities = backfillDarkWeb();
console.log(
  `Backfilled ${actorArticles} threat-actor article(s), ${campaignArticles} campaign article(s), and ${darkWebEntities} dark-web entity/entities with the unified industry classification engine.`,
);
