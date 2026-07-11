import { fetchJson } from "../lib/http.js";
import { extractVendorProduct, extractVendorProductFromAffected } from "../lib/cpe.js";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const LOOKBACK_DAYS = 30;
const DEFAULT_PAGE_SIZE = 20;

function authHeaders() {
  return process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
}

function severityFromScore(score) {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  return "LOW";
}

function parseCveItem(item) {
  const { cve } = item;
  const metric = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0] ?? cve.metrics?.cvssMetricV2?.[0];
  const score = metric?.cvssData.baseScore ?? null;
  const severity = metric?.cvssData.baseSeverity
    ? metric.cvssData.baseSeverity.toUpperCase()
    : score !== null
      ? severityFromScore(score)
      : "UNKNOWN";

  const criteria =
    cve.configurations?.flatMap((node) => node.nodes.flatMap((n) => n.cpeMatch.map((m) => m.criteria))) ?? [];
  const { vendor, product } = extractVendorProductFromAffected(cve.affected) ?? extractVendorProduct(criteria);

  const description =
    cve.descriptions.find((d) => d.lang === "en")?.value ?? cve.descriptions[0]?.value ?? "No description available.";

  return {
    id: cve.id,
    severity,
    cvssScore: score,
    vendor,
    product,
    publishedDate: cve.published,
    description,
    knownExploited: false, // filled in by correlate.js
    epssScore: null, // filled in by correlate.js
    epssPercentile: null, // filled in by correlate.js
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
  };
}

function buildQuery(params) {
  const search = new URLSearchParams();
  if (params.cveId) search.set("cveId", params.cveId);
  if (params.pubStartDate) search.set("pubStartDate", params.pubStartDate.toISOString());
  if (params.pubEndDate) search.set("pubEndDate", params.pubEndDate.toISOString());
  if (params.cvssV3Severity) search.set("cvssV3Severity", params.cvssV3Severity);
  if (params.keywordSearch) search.set("keywordSearch", params.keywordSearch);
  search.set("resultsPerPage", String(params.resultsPerPage ?? DEFAULT_PAGE_SIZE));
  search.set("startIndex", String(params.startIndex ?? 0));
  return search.toString();
}

/** Raw NVD CVE API 2.0 query -- used both by the scheduled sync and the live search route. */
export async function queryCves(params) {
  const data = await fetchJson(`${NVD_URL}?${buildQuery(params)}`, { source: "NVD CVE API", headers: authHeaders() });
  return { totalResults: data.totalResults, records: data.vulnerabilities.map(parseCveItem) };
}

export async function countCves(params) {
  const result = await queryCves({ ...params, resultsPerPage: 1, startIndex: 0 });
  return result.totalResults;
}

/**
 * NVD's date-range queries always return oldest-first with no descending
 * option (confirmed against the live API) -- so genuinely "latest" CVEs
 * require looking up the total count and paging backward from the end of
 * the range, then reversing. This bug (the CVE table showing the *oldest*
 * CVEs in the window) was caught by clicking through the live dashboard,
 * not by typechecking, and this is the fix, now shared by every caller.
 */
export async function fetchLatestCves({ pubStartDate, pubEndDate, cvssV3Severity, keywordSearch, page = 0, pageSize = DEFAULT_PAGE_SIZE }) {
  const filters = { pubStartDate, pubEndDate, cvssV3Severity, keywordSearch };
  const totalResults = await countCves(filters);
  const endIndex = Math.max(0, totalResults - page * pageSize);
  const startIndex = Math.max(0, endIndex - pageSize);
  const take = endIndex - startIndex;
  if (take <= 0) return { totalResults, records: [] };

  const result = await queryCves({ ...filters, startIndex, resultsPerPage: take });
  return { totalResults, records: result.records.reverse() };
}

async function fetchTrend(pubStartDate, pubEndDate) {
  const result = await queryCves({
    pubStartDate,
    pubEndDate,
    cvssV3Severity: "CRITICAL",
    resultsPerPage: 2000, // NVD max page size; comfortably covers 30 days of CRITICAL CVEs
  });

  const byDay = new Map();
  for (const record of result.records) {
    const day = record.publishedDate.slice(0, 10);
    byDay.set(day, (byDay.get(day) ?? 0) + 1);
  }
  return Array.from({ length: LOOKBACK_DAYS }, (_, i) => {
    const date = new Date(pubEndDate);
    date.setUTCDate(date.getUTCDate() - (LOOKBACK_DAYS - 1 - i));
    const key = date.toISOString().slice(0, 10);
    return { date: key, criticalCves: byDay.get(key) ?? 0 };
  });
}

/**
 * Scheduled sync: builds everything the dashboard needs by default (no
 * user-supplied filter) in one cycle -- the live-search branch in
 * routes/dashboard.js calls fetchLatestCves() directly instead, bypassing
 * this cache, since search results are inherently query-specific.
 */
export default {
  id: "nvd",
  label: "NVD CVE API",
  intervalMs: 5 * 60 * 1000, // 5 min
  async fetch() {
    const now = new Date();
    const start = new Date(now);
    start.setUTCDate(start.getUTCDate() - LOOKBACK_DAYS);
    const yesterday = new Date(now);
    yesterday.setUTCHours(yesterday.getUTCHours() - 24);

    const [latestCves, criticalCount30d, highCount30d, mediumCount30d, lowCount30d, newCount24h, trend] = [
      await fetchLatestCves({ pubStartDate: start, pubEndDate: now, pageSize: 100 }),
      await countCves({ pubStartDate: start, pubEndDate: now, cvssV3Severity: "CRITICAL" }),
      await countCves({ pubStartDate: start, pubEndDate: now, cvssV3Severity: "HIGH" }),
      await countCves({ pubStartDate: start, pubEndDate: now, cvssV3Severity: "MEDIUM" }),
      await countCves({ pubStartDate: start, pubEndDate: now, cvssV3Severity: "LOW" }),
      await countCves({ pubStartDate: yesterday, pubEndDate: now }),
      await fetchTrend(start, now),
    ];

    return { latestCves, criticalCount30d, highCount30d, mediumCount30d, lowCount30d, newCount24h, trend };
  },
};
