import * as cache from "../cache.js";
import { threatFeedIocs } from "../threatFeed.js";
import { loadStore, saveStore, listRepos, reposNeedingEnrichment } from "./store.js";
import { fetchRepoContent } from "./contentFetcher.js";
import { extractEntities } from "./extractor.js";
import { classifyRepository } from "./classifier.js";
import { correlateIndicators, enrichCves, countCorroboratingRepos } from "./enrich.js";
import { computeThreatScore } from "./threatScoring.js";
import { log } from "../lib/log.js";
import malwareAttackMap from "../data/malware-attack-map.json" with { type: "json" };

// Bounded per cycle: each repo costs ~2-12 GitHub "core" API calls (README +
// tree + targeted files) plus a live NVD call per newly-seen CVE. Running
// this every 15 min against a small batch keeps working through the backlog
// without competing with the slower discovery sweep for rate-limit budget.
const BATCH_SIZE = 5;
const ENRICHMENT_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // re-enrich a repo at most once/week

const MALWARE_FAMILY_SEED = Object.keys(malwareAttackMap).filter((key) => !key.startsWith("_"));

function maxOf(values) {
  const known = values.filter((v) => v != null);
  return known.length ? Math.max(...known) : null;
}

/**
 * Processes a small batch of not-yet-enriched (or stale) repos: fetches
 * README + targeted rule/IOC files, extracts entities, classifies the repo,
 * correlates indicators against the existing threat feed, enriches any
 * extracted CVEs, and computes a threat score. One repo failing doesn't
 * block the rest of the batch -- it's marked attempted (with the error
 * recorded) so a permanently-broken repo doesn't get retried every cycle
 * forever.
 */
export async function runEnrichment() {
  const store = loadStore();
  const attackData = cache.getEntry("attack").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries ?? [];
  const epssScores = cache.getEntry("epss").data ?? {};
  const feedIocs = threatFeedIocs();

  const batch = reposNeedingEnrichment(store, ENRICHMENT_MAX_AGE_MS, BATCH_SIZE);
  let enrichedCount = 0;

  for (const repo of batch) {
    try {
      const [owner, name] = repo.fullName.split("/");
      const { combinedText } = await fetchRepoContent(owner, name, repo.defaultBranch);

      const extracted = extractEntities(combinedText, {
        techniques: attackData?.techniques ?? [],
        groups: attackData?.groups ?? [],
        malwareFamilies: MALWARE_FAMILY_SEED,
      });

      const categories = classifyRepository(repo, combinedText);
      const correlation = correlateIndicators(extracted, feedIocs);
      const cveEnrichment = await enrichCves(extracted.cveIds, { kevEntries, epssScores });
      const corroboratingRepoCount = countCorroboratingRepos(extracted.cveIds, listRepos(store), repo.fullName);

      const { score, breakdown } = computeThreatScore({
        stars: repo.stars,
        lastCommitDate: repo.lastCommitDate,
        cvssScore: cveEnrichment.length ? maxOf(cveEnrichment.map((c) => c.cvssScore)) : null,
        epssScore: cveEnrichment.length ? maxOf(cveEnrichment.map((c) => c.epssScore)) : null,
        knownExploited: cveEnrichment.length ? cveEnrichment.some((c) => c.knownExploited) : null,
        matchedFeeds: correlation.feedsChecked ? correlation.matchedFeeds : null,
        feedsChecked: correlation.feedsChecked || null,
        corroboratingRepoCount,
      });

      Object.assign(repo, {
        categories,
        extracted,
        correlation,
        cveEnrichment,
        threatScore: { score, breakdown },
        lastEnrichedAt: new Date().toISOString(),
        enrichmentError: undefined,
      });
      enrichedCount++;
    } catch (error) {
      log.error("github-enrichment", `enriching ${repo.fullName} failed: ${error.message}`);
      repo.lastEnrichedAt = new Date().toISOString();
      repo.enrichmentError = error.message;
    }
  }

  saveStore(store);
  return {
    repoCount: listRepos(store).length,
    enrichedThisRun: enrichedCount,
    pendingEnrichment: reposNeedingEnrichment(store, ENRICHMENT_MAX_AGE_MS, Infinity).length,
  };
}
