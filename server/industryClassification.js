// Generalized, reusable industry-relevance classification -- the single
// engine every industry-facing feature in this app now calls through,
// replacing three previously-separate, mismatched implementations:
//   - server/newsCorrelation.js's old matchIndustries() (4-bucket LSHC/TMT/
//     FSI/Consumer, fed threat-actor/campaign/dark-web per-article tagging)
//   - server/emergingThreatsRanking.js's old matchIndustries() (a DIFFERENT
//     14-sector taxonomy, fed the Industry Intelligence page/heatmap)
//   - server/industryCorrelation.js's industriesFromText() (a workaround
//     for the above two never agreeing with each other)
//
// Root problem this fixes (confirmed live): "Critical One-Click Vulnerability
// in Atlassian's Rovo AI Exposed Enterprise Data" never gets tagged to any
// industry by ANY of the above, because none of them look past explicit
// sector words in the title -- "Atlassian Rovo" carries zero of the phrases
// in industry-map-21.json. This file adds a second, independent signal
// (server/data/technology-category-map.json: which industries commonly run
// which enterprise technology) so a product/vendor mention is enough to
// establish relevance even when the source never names a sector -- and
// keeps that signal EXPLICITLY WEAKER than an explicit textual claim by
// returning a separate, lower tier for it (see INDUSTRY_TIER below), never
// silently equating "uses this software" with "was targeted."
//
// This module only classifies TEXT and VENDOR/PRODUCT pairs. Entity-level
// signals that need more than text (an actor's own accumulated targeting
// history, a campaign's victim list, cross-linkage between entities) still
// live in server/industryCorrelation.js, which calls into this module's
// primitives (matchIndustries/matchTechnologyIndustries) instead of
// duplicating the matching logic.
import industryKeywords from "./data/industry-map-21.json" with { type: "json" };
import technologyMap from "./data/technology-category-map.json" with { type: "json" };

export const INDUSTRY_CATALOG = Object.keys(industryKeywords).filter((k) => !k.startsWith("_"));

/**
 * Five-value relevance vocabulary -- deliberately keeps "explicitly
 * targeted" and "runs software commonly used in this sector" as different
 * claims with different confidence, per this platform's own evidence-tier
 * discipline (see server/investigation/evidence.js's direct/corroborating/
 * indirect split, the same principle applied here to industries instead of
 * IOC reputation).
 *   DIRECT               -- source text explicitly names the industry as a target/victim.
 *   INDIRECT_ASSOCIATED  -- not established by THIS source, but documented
 *                            elsewhere in this platform's own data (an
 *                            actor's historical targeting, a linked
 *                            malware/actor/campaign that IS direct-tier).
 *   TECHNOLOGY_RELEVANT  -- the affected product/vendor is one this
 *                            industry specifically, commonly runs (a
 *                            "narrow" technology category).
 *   POTENTIALLY_EXPOSED  -- the affected product/vendor is broadly used
 *                            across many sectors (a "broad" technology
 *                            category) -- organizations here COULD be
 *                            exposed, nothing more is claimed.
 *   NONE                 -- no signal at all; never invented.
 */
export const INDUSTRY_TIER = {
  DIRECT: "DIRECT",
  INDIRECT_ASSOCIATED: "INDIRECT_ASSOCIATED",
  TECHNOLOGY_RELEVANT: "TECHNOLOGY_RELEVANT",
  POTENTIALLY_EXPOSED: "POTENTIALLY_EXPOSED",
  NONE: "NONE",
};

export const INDUSTRY_TIER_LABEL = {
  DIRECT: "Directly Targeted",
  INDIRECT_ASSOCIATED: "Indirectly Targeted / Associated",
  TECHNOLOGY_RELEVANT: "Technology-Relevant",
  POTENTIALLY_EXPOSED: "Potentially Exposed",
  NONE: "No Established Industry Link",
};

// Ranks tiers for "which wins when the same industry is hit by more than
// one signal" -- always keep the strongest claim, never let a weaker one
// downgrade a stronger one already established for the same industry.
// Exported so other modules that need to merge tiers across multiple
// classification calls (e.g. investigationGraph.js re-deriving a per-value
// tier across an entity's whole article history) don't reimplement this.
export const INDUSTRY_TIER_RANK = { DIRECT: 4, INDIRECT_ASSOCIATED: 3, TECHNOLOGY_RELEVANT: 2, POTENTIALLY_EXPOSED: 1, NONE: 0 };
const TIER_RANK = INDUSTRY_TIER_RANK;

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Leading/trailing word-boundary match (not a naive substring -- avoids e.g. "power" matching inside "empower"), case-insensitive. Same convention industry-map-14.json established. */
function boundaryPattern(phrase) {
  return new RegExp(`(?:^|[^a-z0-9])${escapeRegex(phrase.toLowerCase())}(?:[^a-z0-9]|$)`, "i");
}

const INDUSTRY_PATTERNS = Object.entries(industryKeywords)
  .filter(([k]) => !k.startsWith("_"))
  .map(([industry, phrases]) => [industry, phrases.map(boundaryPattern)]);

// Single-word/short-label synonyms real upstream data uses verbatim (ATT&CK
// group targetIndustries, ransomware.live's own sector field) that the
// phrase list's multi-word entries don't literally contain -- moved here
// from server/industryCorrelation.js (formerly duplicated per-consumer).
// Deliberately conservative: an ambiguous single word is left unmapped
// rather than force-guessed into one sector.
const INDUSTRY_SYNONYM_PATTERNS = Object.entries({
  financial: "Financial Services",
  finance: "Financial Services",
  fsi: "Financial Services",
  insurer: "Insurance",
  health: "Healthcare",
  hospital: "Healthcare",
  medical: "Healthcare",
  lshc: "Healthcare",
  biotech: "Pharmaceuticals",
  defense: "Defense & Aerospace",
  military: "Defense & Aerospace",
  aerospace: "Defense & Aerospace",
  federal: "Government",
  industrial: "Manufacturing",
  automotive: "Automotive",
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
  legal: "Professional Services",
  accounting: "Professional Services",
  consulting: "Professional Services",
  construction: "Construction",
  agriculture: "Agriculture",
  farming: "Agriculture",
  "real estate": "Real Estate",
}).map(([word, industry]) => [boundaryPattern(word), industry]);

/**
 * EXPLICIT TARGETING signal only -- every industry a free-text blob
 * (article title+summary, entity description, campaign/actor targeting
 * text) literally names via phrase or synonym match. Does not look at
 * technology/vendor signal at all -- see matchTechnologyIndustries for that.
 * @param {string} text
 * @returns {string[]}
 */
export function matchIndustries(text) {
  if (!text) return [];
  const hits = new Set();
  for (const [industry, patterns] of INDUSTRY_PATTERNS) {
    if (patterns.some((re) => re.test(text))) hits.add(industry);
  }
  for (const [re, industry] of INDUSTRY_SYNONYM_PATTERNS) {
    if (re.test(text)) hits.add(industry);
  }
  return [...hits];
}

const TECH_PATTERNS = Object.entries(technologyMap.categories).flatMap(([category, def]) =>
  def.vendors.map((vendor) => ({ category, vendor, industries: def.industries, specificity: def.specificity, re: boundaryPattern(vendor) })),
);

/**
 * AFFECTED TECHNOLOGY / PRODUCT signal -- scans text for a known enterprise
 * vendor/product mention and maps it to the industries that commonly run
 * that category of technology (server/data/technology-category-map.json).
 * This is what surfaces relevance for a report that never names a sector
 * at all (the Atlassian Rovo case). Each hit is tiered by the category's
 * own `specificity`: a narrow (industry-specific) category is
 * TECHNOLOGY_RELEVANT; a broad (cross-sector) category is the weaker
 * POTENTIALLY_EXPOSED for every industry it lists.
 * @param {string} text
 * @returns {{industry: string, tier: "TECHNOLOGY_RELEVANT"|"POTENTIALLY_EXPOSED", category: string, matchedVendor: string}[]}
 */
export function matchTechnologyIndustries(text) {
  if (!text) return [];
  const byIndustry = new Map();
  for (const p of TECH_PATTERNS) {
    if (!p.re.test(text)) continue;
    const tier = p.specificity === "narrow" ? INDUSTRY_TIER.TECHNOLOGY_RELEVANT : INDUSTRY_TIER.POTENTIALLY_EXPOSED;
    for (const industry of p.industries) {
      const existing = byIndustry.get(industry);
      if (existing && TIER_RANK[existing.tier] >= TIER_RANK[tier]) continue;
      byIndustry.set(industry, { industry, tier, category: p.category, matchedVendor: p.vendor });
    }
  }
  return [...byIndustry.values()];
}

/**
 * Same technology signal as matchTechnologyIndustries, but for callers that
 * already know the affected vendor/product directly (CVEs, via this app's
 * existing CPE vendor/product extraction -- see server/lib/cpe.js) rather
 * than having to re-extract it from free text.
 * @param {string} [vendor]
 * @param {string} [product]
 */
export function matchVendorProductIndustries(vendor, product) {
  const text = [vendor, product].filter(Boolean).join(" ");
  return matchTechnologyIndustries(text);
}

/**
 * The full tiered classification for one piece of text (optionally paired
 * with a known vendor/product) -- combines EXPLICIT TARGETING and
 * AFFECTED TECHNOLOGY into one deduped result set, one entry per industry,
 * always keeping the strongest tier when both signals hit the same
 * industry. This is what section F (CVE/vulnerability exposure) and every
 * article-level classification in this app should call.
 * @param {string} text
 * @param {{vendor?: string, product?: string}} [context]
 * @returns {{industry: string, tier: string, reason: string}[]}
 */
export function classifyIndustryRelevance(text, { vendor, product } = {}) {
  const results = new Map();

  for (const industry of matchIndustries(text)) {
    results.set(industry, { industry, tier: INDUSTRY_TIER.DIRECT, reason: `Source text explicitly references the ${industry} sector.` });
  }

  const techText = vendor || product ? `${text ?? ""} ${vendor ?? ""} ${product ?? ""}` : text;
  for (const hit of matchTechnologyIndustries(techText)) {
    const existing = results.get(hit.industry);
    if (existing && TIER_RANK[existing.tier] >= TIER_RANK[hit.tier]) continue;
    const reason =
      hit.tier === INDUSTRY_TIER.TECHNOLOGY_RELEVANT
        ? `${hit.matchedVendor} (${hit.category}) is commonly deployed by organizations in ${hit.industry}.`
        : `${hit.matchedVendor} (${hit.category}) may be deployed by organizations in ${hit.industry}, among many other sectors.`;
    results.set(hit.industry, { industry: hit.industry, tier: hit.tier, reason });
  }

  return [...results.values()];
}

/**
 * Convenience wrapper for the common "which industries should this article
 * be tagged with at all" use case (per-mention tagging on threat-actor/
 * campaign/dark-web entities, news feed tagging) -- a flat, deduped
 * industry-name list combining explicit-targeting AND technology-relevance
 * hits, with no tier distinction. Callers that need the tier (industry
 * ranking, CVE exposure, the Industry Intelligence briefing) should use
 * classifyIndustryRelevance instead.
 * @param {string} text
 * @returns {string[]}
 */
export function taggingIndustries(text) {
  return [...new Set(classifyIndustryRelevance(text).map((r) => r.industry))];
}
