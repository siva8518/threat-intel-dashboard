// One-time historical migration (Phase F of the IOC extraction pipeline
// overhaul): server/iocExtractionJob.js only ever sees articles still present
// in the live "news" cache (server/cache.js), which rotates older items out.
// This script recovers IOCs from every article this app has ANY existing
// record of -- malware/actor/campaign/dark-web/tool entity `articles[]`
// lists, plus every stored AI Summarization report -- so already-ingested
// intelligence gets the same canonical-store coverage as newly-ingested
// articles, without requiring the user to wait for those same stories to be
// re-published. Idempotent via server/iocIntelligence.js's own
// processed-article ledger plus upsertIndicator()'s canonicalId dedup -- safe
// to re-run; a second run should add ~0 new IOCs.
//   node scripts/backfillIocIntelligence.js
import "dotenv/config";
import { extractEntities } from "../server/githubIntel/extractor.js";
import { fetchArticleText } from "../server/lib/articleText.js";
import * as iocIntel from "../server/iocIntelligence.js";
import { extractContextSnippet } from "../server/iocClassification.js";
import * as malwareIntel from "../server/malwareIntelligence.js";
import * as actorIntel from "../server/threatActorIntelligence.js";
import * as campaignIntel from "../server/campaignIntelligence.js";
import * as darkWebIntel from "../server/darkWebIntelligence.js";
import * as toolIntel from "../server/toolIntelligence.js";
import { getAllReports } from "../server/aiThreatSummaryStore.js";

// A one-time backlog-clearing script, not a recurring job -- politeness
// pacing only needs to avoid hammering source sites concurrently, same
// rationale as server/iocExtractionJob.js#ARTICLE_FETCH_PACING_MS.
const ARTICLE_FETCH_PACING_MS = 400;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * server/aiThreatSummary.js#extractIocs() already collapsed ipv4/ipv6 into
 * one "ipAddresses" bucket and sha256/sha1/md5 into one "hashes" bucket for
 * report display -- reversing that requires inferring the fine-grained type
 * back from the value's own shape (colon present = v6; hash length = algo),
 * not from anything the report itself recorded.
 */
const REPORT_CATEGORY_TYPE_MAP = {
  domains: "domain",
  urls: "url",
  emailAddresses: "email",
  registryKeys: "registryKey",
  filePaths: "filePath",
  fileNames: "fileName",
  ports: "port",
  eventIds: "eventId",
  namedPipes: "namedPipe",
  mutexes: "mutex",
  scheduledTasks: "scheduledTask",
  services: "service",
  cweIds: "cwe",
  cliCommands: "cliCommand",
  userAgents: "userAgent",
};

function candidatesFromReportIocs(iocs) {
  const candidates = [];
  if (!iocs) return candidates;
  for (const value of iocs.ipAddresses ?? []) candidates.push({ type: value.includes(":") ? "ipv6" : "ipv4", value });
  for (const value of iocs.hashes ?? []) {
    const type = value.length === 64 ? "sha256" : value.length === 40 ? "sha1" : value.length === 32 ? "md5" : null;
    if (type) candidates.push({ type, value });
  }
  for (const [category, type] of Object.entries(REPORT_CATEGORY_TYPE_MAP)) {
    for (const value of iocs[category] ?? []) candidates.push({ type, value });
  }
  return candidates;
}

/** Union of every already-ingested article this app has any record of, deduped by link. */
function collectHistoricalArticles() {
  const byLink = new Map();
  for (const store of [malwareIntel, actorIntel, campaignIntel, darkWebIntel, toolIntel]) {
    for (const entity of store.getAllEntities()) {
      for (const article of entity.articles ?? []) {
        if (!article.link || byLink.has(article.link)) continue;
        byLink.set(article.link, { title: article.title, link: article.link, source: article.source, publishedDate: article.publishedDate });
      }
    }
  }
  const reportByLink = new Map();
  for (const report of getAllReports()) {
    if (!report.articleLink) continue;
    reportByLink.set(report.articleLink, report);
    if (!byLink.has(report.articleLink)) {
      byLink.set(report.articleLink, { title: report.articleTitle, link: report.articleLink, source: report.articleSource, publishedDate: report.publishedDate });
    }
  }
  return { articles: [...byLink.values()], reportByLink };
}

function upsertCandidates(candidates, article, extractionMethod, textForSnippet) {
  for (const { type, value } of candidates) {
    iocIntel.upsertIndicator(type, value, {
      articleTitle: article.title,
      articleLink: article.link,
      articleSource: article.source,
      publishedDate: article.publishedDate,
      contextSnippet: textForSnippet ? extractContextSnippet(textForSnippet, value) : null,
      extractionMethod,
    });
  }
}

async function processArticle(article, report) {
  const fullText = await fetchArticleText(article.link, article.source);
  if (fullText) {
    const candidates = iocIntel.flattenExtractedCandidates(extractEntities(fullText, {}));
    upsertCandidates(candidates, article, "regex-fulltext", fullText);
    return { tier: "fullTextRecovered", candidateCount: candidates.length };
  }

  // Full text is unreachable (old URL, paywall, 404 -- expected for
  // historical articles, not a fatal error) -- fall back to whatever richer
  // record already exists for this link before giving up.
  if (report?.iocs) {
    const candidates = candidatesFromReportIocs(report.iocs);
    upsertCandidates(candidates, article, "backfill-from-report", null);
    return { tier: "fallbackOnly", candidateCount: candidates.length };
  }

  if (article.title && article.title.trim().length > 0) {
    const candidates = iocIntel.flattenExtractedCandidates(extractEntities(article.title, {}));
    upsertCandidates(candidates, article, "regex-title-summary", article.title);
    return { tier: "fallbackOnly", candidateCount: candidates.length };
  }

  return { tier: "totallyUnrecoverable", candidateCount: 0 };
}

async function main() {
  const { articles, reportByLink } = collectHistoricalArticles();
  const unprocessed = articles.filter((a) => !iocIntel.isIocExtractionProcessed(a.link));
  console.log(`Found ${articles.length} historical article(s) on record, ${unprocessed.length} not yet run through IOC extraction.`);

  const startCount = iocIntel.getEntityCount();
  let fullTextRecovered = 0;
  let fallbackOnly = 0;
  let totallyUnrecoverable = 0;
  let candidatesSeen = 0;

  for (const [index, article] of unprocessed.entries()) {
    if (index > 0) await sleep(ARTICLE_FETCH_PACING_MS);
    try {
      const { tier, candidateCount } = await processArticle(article, reportByLink.get(article.link));
      if (tier === "fullTextRecovered") fullTextRecovered += 1;
      else if (tier === "fallbackOnly") fallbackOnly += 1;
      else totallyUnrecoverable += 1;
      candidatesSeen += candidateCount;
    } catch (error) {
      totallyUnrecoverable += 1;
      console.error(`  failed on "${(article.title ?? article.link).slice(0, 60)}": ${error.message}`);
    }
    iocIntel.markIocExtractionProcessed(article.link);
    if ((index + 1) % 50 === 0) {
      iocIntel.saveAfterMentions();
      console.log(`  ...${index + 1}/${unprocessed.length} processed`);
    }
  }

  iocIntel.saveAfterMentions();
  const linked = iocIntel.backfillMissingAssociations(malwareIntel.getAllEntities(), actorIntel.getAllEntities(), campaignIntel.getAllEntities());
  if (linked > 0) iocIntel.saveAfterMentions();

  console.log("\nBackfill complete.");
  console.log(`  fullTextRecovered: ${fullTextRecovered}`);
  console.log(`  fallbackOnly: ${fallbackOnly}`);
  console.log(`  totallyUnrecoverable: ${totallyUnrecoverable}`);
  console.log(`  candidates seen: ${candidatesSeen}`);
  console.log(`  new unique IOCs added: ${iocIntel.getEntityCount() - startCount}`);
  console.log(`  associations backfilled: ${linked}`);
}

main().catch((error) => {
  console.error("Backfill failed:", error);
  process.exit(1);
});
