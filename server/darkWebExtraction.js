// Dark-web-finding validation for article headline + summary extraction.
// Candidates come from the combined per-article call in
// server/combinedExtraction.js -- this is NOT direct dark-web-forum
// scraping. Every finding here originates from an OSINT source already in
// server/connectors/newsFeeds.js's FEEDS list -- vendors and researchers
// (KELA, Cyble, SOCRadar, Constella Intelligence, Silobreaker, Recorded
// Future, Intel 471, ransomware-tracker leak-site posts, etc.) who
// themselves monitor underground forums/marketplaces/Telegram channels and
// publish what they find. Every candidate still passes through
// validateCandidates below before server/darkWebIntelligence.js#upsertMention
// ever sees it.
export const MAX_FINDINGS_PER_ARTICLE = 3;

export const DARKWEB_TYPES = ["Data Leak", "Credential Dump", "Initial Access Listing", "Marketplace Listing", "Forum Discussion", "Extortion Threat", "Other"];

const MAX_PLATFORM_LENGTH = 40;
const MAX_VICTIM_LENGTH = 80;

// Noise filtering on the model's own output, same category as
// server/malwareExtraction.js's GENERIC_STOPWORDS -- catches vague labels
// the model sometimes produces from an article with no real dark-web angle.
const GENERIC_STOPWORDS = new Set(["dark web activity", "underground forum post", "forum post", "marketplace listing", "data leak", "unknown", "unnamed"]);

// A handful of non-answers the model sometimes puts in the `platform` field
// when the article doesn't actually name one -- treated the same as null.
const GENERIC_PLATFORM_VALUES = new Set(["dark web", "the dark web", "darknet", "underground forum", "a forum", "unknown", "unnamed", "n/a"]);

// Confirmed live: a stats/trend-report article with no single specific
// finding ("New tutorials on underground hacking forums have roughly
// doubled") got the combined-extraction prompt's own placeholder example
// ("Acme Corp customer database") echoed back as a fabricated finding --
// the model reused few-shot example wording instead of returning [] for a
// article with nothing concrete to extract. The prompt itself was tightened
// to stop this, but this pattern-match is kept as a second, code-level
// guard against the same failure mode recurring under different wording.
const PLACEHOLDER_PATTERN = /\bacme\b|\bexample corp\b|\bfoo\s*corp\b|\btest\s*company\b|\b123456\b/i;

/**
 * Filters raw LLM output before it's ever allowed to become a record.
 * `articleSource` guards against the model echoing the publisher's own name
 * back as a finding label -- the same guard already used for malware/actor/
 * campaign candidates.
 */
export function validateCandidates(candidates, { articleSource }) {
  const seen = new Set();
  const valid = [];
  for (const raw of candidates.slice(0, MAX_FINDINGS_PER_ARTICLE)) {
    const label = (raw.label ?? "").trim();
    const lower = label.toLowerCase();
    if (label.length < 6 || label.length > 100) continue;
    if (GENERIC_STOPWORDS.has(lower)) continue;
    if (PLACEHOLDER_PATTERN.test(label)) continue;
    if (lower === (articleSource ?? "").toLowerCase()) continue;
    if (seen.has(lower)) continue;
    seen.add(lower);

    const type = DARKWEB_TYPES.includes(raw.type) ? raw.type : "Other";
    const platformRaw = typeof raw.platform === "string" ? raw.platform.trim() : "";
    const platform = platformRaw && !GENERIC_PLATFORM_VALUES.has(platformRaw.toLowerCase()) ? platformRaw.slice(0, MAX_PLATFORM_LENGTH) : null;
    const victimRaw = typeof raw.victimOrg === "string" ? raw.victimOrg.trim() : "";
    const victimOrg = victimRaw && victimRaw.length >= 2 ? victimRaw.slice(0, MAX_VICTIM_LENGTH) : null;

    valid.push({ label, type, platform, victimOrg });
  }
  return valid;
}
