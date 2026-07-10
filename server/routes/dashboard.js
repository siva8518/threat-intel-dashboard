import { Router } from "express";
import * as cache from "../cache.js";
import { connectors } from "../connectors/index.js";
import { fetchLatestCves, queryCves } from "../connectors/nvd.js";
import { correlateCves, computeTrendingMalware, computeAttackTechniquesObserved, mergeThreatActors, computeActorIndustryHeatmap, computeGeoTargeting, industryForSector } from "../correlate.js";
import { threatFeedIocs } from "../threatFeed.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { checkIndicator as checkOtx } from "../connectors/otx.js";
import { checkIndicator as checkAbuseIpdb } from "../connectors/abuseipdb.js";
import { checkIndicator as checkPulsedive } from "../connectors/pulsedive.js";
import { checkIndicator as checkVirusTotal } from "../lookups/virustotal.js";
import { checkIndicator as checkGreyNoise } from "../lookups/greynoise.js";
import { checkIndicator as checkShodan } from "../lookups/shodan.js";
import { checkIndicator as checkHybridAnalysis } from "../lookups/hybridAnalysis.js";
import { checkIndicator as checkLeakix } from "../lookups/leakix.js";
import { throttleAndCache } from "../lib/lookupLimiter.js";
import { listThreatActors, searchThreatActors, buildThreatActorProfile } from "../actorProfile.js";
import { getAllGithubRepos, computeTopCves } from "../githubIntel/index.js";
import { buildCveProfile } from "../cveProfile.js";
import { buildMalwareProfile } from "../malwareProfile.js";
import { buildExecutiveSummary } from "../executiveSummary.js";
import { buildCorrelationClusters } from "../correlationEngine.js";
import { getTaggedNewsItems } from "../newsCorrelation.js";
import { buildTodaySecurityEvents } from "../todaySecurityEvents.js";
import { buildDailySummary } from "../dailySummary.js";
import { buildTopThreatActorsToday } from "../topThreatActorsToday.js";

export const router = Router();

const LOOKBACK_DAYS = 30;

// --- Summary -----------------------------------------------------------
router.get("/dashboard/summary", (_req, res) => {
  const nvd = cache.getEntry("nvd").data;
  const kev = cache.getEntry("cisa-kev").data;
  const iocs = threatFeedIocs();
  const health = buildHealth();

  res.json({
    criticalCves30d: nvd?.criticalCount30d ?? null,
    newCves24h: nvd?.newCount24h ?? null,
    knownExploitedVulnerabilities: kev?.count ?? null,
    maliciousUrls: iocs.length,
    sourcesOnline: health.filter((h) => h.online).length,
    sourcesTotal: health.length,
  });
});

// --- Executive Threat Summary (hero rollup, see server/executiveSummary.js) ---
router.get("/dashboard/executive-summary", (_req, res) => {
  const nvd = cache.getEntry("nvd").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries ?? [];
  const attackData = cache.getEntry("attack").data;
  const otxSignals = cache.getEntry("otx").data?.actorSignals ?? [];
  const campaigns = getRansomwareCampaigns();
  const iocs = threatFeedIocs();

  const summary = buildExecutiveSummary({
    criticalCves30d: nvd?.criticalCount30d ?? 0,
    kevEntries,
    threatFeedIocs: iocs,
    ransomwareCampaigns: campaigns,
    trendingMalware: computeTrendingMalware(iocs, attackData?.techniques ?? []),
    githubTopCves: computeTopCves(getAllGithubRepos(), 10),
    industryHeatmap: computeActorIndustryHeatmap(campaigns, { country: null }),
    geoTargeting: computeGeoTargeting(campaigns),
    mergedActors: mergeThreatActors(campaigns, otxSignals),
  });

  res.json(summary);
});

// --- Threat Correlation Engine (see server/correlationEngine.js) --------
router.get("/dashboard/correlation-engine", (_req, res) => {
  const cards = buildCorrelationClusters({
    threatFeedIocs: threatFeedIocs(),
    attackData: cache.getEntry("attack").data,
    ransomwareCampaigns: getRansomwareCampaigns(),
    kevEntries: cache.getEntry("cisa-kev").data?.entries ?? [],
    githubRepos: getAllGithubRepos(),
  });
  res.json({ cards });
});

// --- CVEs (cached default view, live for search/pagination/filters) ----
router.get("/dashboard/cves", async (req, res) => {
  const { keyword, severity, page = "0", pageSize = "20" } = req.query;
  const isDefaultView = !keyword && !severity && page === "0";

  try {
    const kevEntries = cache.getEntry("cisa-kev").data?.entries ?? [];
    const epssScores = cache.getEntry("epss").data ?? {};

    if (isDefaultView) {
      const nvd = cache.getEntry("nvd").data;
      if (!nvd) return res.status(503).json({ error: "NVD data is still syncing, try again shortly" });
      const records = nvd.latestCves.records.slice(0, Number(pageSize));
      return res.json({ totalResults: nvd.latestCves.totalResults, records: correlateCves(records, kevEntries, epssScores) });
    }

    const now = new Date();
    const start = new Date(now);
    start.setUTCDate(start.getUTCDate() - LOOKBACK_DAYS);

    const result = await fetchLatestCves({
      pubStartDate: start,
      pubEndDate: now,
      cvssV3Severity: severity || undefined,
      keywordSearch: keyword || undefined,
      page: Number(page),
      pageSize: Number(pageSize),
    });
    res.json({ totalResults: result.totalResults, records: correlateCves(result.records, kevEntries, epssScores) });
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

router.get("/dashboard/cve-trend", (_req, res) => {
  const nvd = cache.getEntry("nvd").data;
  res.json(nvd?.trend ?? []);
});

// Live single-CVE lookup by ID -- unlike /dashboard/cves (which is scoped to
// the last 30 days even for keyword searches), this reaches any CVE
// regardless of age via NVD's own cveId= query param. Same enrichment
// (KEV/EPSS) as every other CVE record in this app. Used by the MCP server's
// lookup_cve tool, but a normal route in its own right.
router.get("/dashboard/cve/:cveId", async (req, res) => {
  const cveId = req.params.cveId.toUpperCase();
  try {
    const result = await queryCves({ cveId, resultsPerPage: 1 });
    const record = result.records[0];
    if (!record) return res.status(404).json({ error: `CVE ${cveId} not found` });

    const kevEntries = cache.getEntry("cisa-kev").data?.entries ?? [];
    const epssScores = cache.getEntry("epss").data ?? {};
    const [enriched] = correlateCves([record], kevEntries, epssScores);
    res.json(enriched);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// Cross-reference correlation for the CVE detail drawer -- everything a CVE
// relates to elsewhere in this app (actors/campaigns/malware/techniques via
// ATT&CK's own CVE citations, IOCs one hop out through that malware, GitHub
// PoCs, and news mentions). See server/cveProfile.js for exactly what is and
// isn't correlatable and why.
router.get("/dashboard/cve-profile/:cveId", (req, res) => {
  const cveId = req.params.cveId.toUpperCase();
  const profile = buildCveProfile(cveId, {
    attackData: cache.getEntry("attack").data,
    newsItems: cache.getEntry("news").data?.items ?? [],
    githubRepos: getAllGithubRepos(),
  });
  res.json(profile);
});

// Cross-reference correlation for the malware-family detail drawer -- see
// server/malwareProfile.js.
router.get("/dashboard/malware-profile/:family", (req, res) => {
  const profile = buildMalwareProfile(req.params.family, {
    attackData: cache.getEntry("attack").data,
    newsItems: cache.getEntry("news").data?.items ?? [],
  });
  res.json(profile);
});

// --- CVE Program (cve.org) recent record activity, distinct from NVD -----
router.get("/dashboard/cve-program-activity", (_req, res) => {
  const entry = cache.getEntry("cve-project").data;
  res.json(entry ?? { fetchedAt: null, newCves: [], updatedCves: [] });
});

// --- KEV -----------------------------------------------------------------
router.get("/dashboard/kev", (_req, res) => {
  const kev = cache.getEntry("cisa-kev");
  if (kev.error && !kev.data) return res.status(502).json({ error: kev.error });
  res.json(kev.data ?? { count: 0, entries: [] });
});

// --- Threat feed (deduped across all IOC sources incl. OTX) -------------
router.get("/dashboard/threat-feed", (_req, res) => {
  res.json({ iocs: threatFeedIocs().slice(0, 200) });
});

// --- Trending malware + ATT&CK techniques (derived from threat feed) ----
// attack.js's fetch() returns { techniques, groups, software, campaigns } (expanded
// for Threat Actor Profiles) -- these two routes only ever need the flat technique list.
router.get("/dashboard/malware-trending", (_req, res) => {
  const attackIndex = cache.getEntry("attack").data?.techniques ?? [];
  res.json(computeTrendingMalware(threatFeedIocs(), attackIndex));
});

router.get("/dashboard/attack-techniques", (_req, res) => {
  const attackIndex = cache.getEntry("attack").data?.techniques ?? [];
  res.json(computeAttackTechniquesObserved(threatFeedIocs(), attackIndex));
});

// --- Ransomware campaigns + threat actor activity ------------------------
// Merged across ransomware.live + RansomWatch + RansomLook -- see
// server/ransomwareCampaigns.js for the dedupe logic.
router.get("/dashboard/ransomware", (_req, res) => {
  // `industry` is the same bucket the Executive Threat Summary's "Industries
  // Targeted" facts use (server/correlate.js#industryForSector) -- tagged
  // here so clicking one of those facts can filter this exact list client-side.
  const campaigns = getRansomwareCampaigns()
    .slice(0, 50)
    .map((c) => ({ ...c, industry: industryForSector(c.sector) }));
  res.json({ campaigns });
});

router.get("/dashboard/threat-actors", (_req, res) => {
  const otxSignals = cache.getEntry("otx").data?.actorSignals ?? [];
  res.json(mergeThreatActors(getRansomwareCampaigns(), otxSignals).slice(0, 30));
});

// --- Threat Actor Profiles (primary source: MITRE ATT&CK Groups) --------
router.get("/dashboard/threat-actor-profiles", (_req, res) => {
  const attackData = cache.getEntry("attack").data;
  res.json({ actors: listThreatActors(attackData) });
});

router.get("/dashboard/threat-actor-profiles/search", (req, res) => {
  const attackData = cache.getEntry("attack").data;
  res.json({ actors: searchThreatActors(attackData, req.query.q ?? "") });
});

router.get("/dashboard/threat-actor-profiles/:attackId", async (req, res) => {
  const attackData = cache.getEntry("attack").data;
  if (!attackData) return res.status(503).json({ error: "ATT&CK data is still syncing, try again shortly" });

  try {
    const profile = await buildThreatActorProfile(req.params.attackId, attackData, {
      threatFeedIocs: threatFeedIocs(),
      newsItems: cache.getEntry("news").data?.items ?? [],
      ransomwareCampaigns: getRansomwareCampaigns(),
      malpediaActors: cache.getEntry("malpedia").data?.actors ?? [],
    });
    if (!profile) return res.status(404).json({ error: `No ATT&CK group found for id "${req.params.attackId}"` });
    res.json(profile);
  } catch (error) {
    res.status(502).json({ error: error.message });
  }
});

// --- Security news (tagged for the newsroom view, see server/newsCorrelation.js) ---
router.get("/dashboard/news", (_req, res) => {
  const items = getTaggedNewsItems({
    newsItems: cache.getEntry("news").data?.items,
    attackData: cache.getEntry("attack").data,
    ransomwareCampaigns: getRansomwareCampaigns(),
    threatFeedIocs: threatFeedIocs(),
    kevEntries: cache.getEntry("cisa-kev").data?.entries,
    epssScores: cache.getEntry("epss").data,
  });
  res.json({ items });
});

// --- Top Security Events Today (same-calendar-day rollup, see server/todaySecurityEvents.js) ---
router.get("/dashboard/today-events", (_req, res) => {
  const events = buildTodaySecurityEvents({
    kevEntries: cache.getEntry("cisa-kev").data?.entries,
    otxActorSignals: cache.getEntry("otx").data?.actorSignals,
    ransomwareCampaigns: getRansomwareCampaigns(),
    threatFeedIocs: threatFeedIocs(),
    githubRepos: getAllGithubRepos(),
  });
  res.json(events);
});

// --- Daily Summary (short rule-based rollup, see server/dailySummary.js) ---
router.get("/dashboard/daily-summary", (_req, res) => {
  const attackData = cache.getEntry("attack").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries;
  const otxActorSignals = cache.getEntry("otx").data?.actorSignals;
  const ransomwareCampaigns = getRansomwareCampaigns();
  const iocs = threatFeedIocs();
  const githubRepos = getAllGithubRepos();
  const newsItems = getTaggedNewsItems({
    newsItems: cache.getEntry("news").data?.items,
    attackData,
    ransomwareCampaigns,
    threatFeedIocs: iocs,
    kevEntries,
    epssScores: cache.getEntry("epss").data,
  });

  const todayEvents = buildTodaySecurityEvents({ kevEntries, otxActorSignals, ransomwareCampaigns, threatFeedIocs: iocs, githubRepos, newsItems });
  const trendingMalware = computeTrendingMalware(iocs, attackData?.techniques ?? []);

  const summary = buildDailySummary({ todayEvents, ransomwareCampaigns, threatFeedIocs: iocs, newsItems, trendingMalware });
  res.json(summary);
});

// --- Top Threat Actors Today (same-calendar-day leaderboard, see server/topThreatActorsToday.js) ---
router.get("/dashboard/top-threat-actors-today", (_req, res) => {
  const attackData = cache.getEntry("attack").data;
  const kevEntries = cache.getEntry("cisa-kev").data?.entries;
  const ransomwareCampaigns = getRansomwareCampaigns();
  const otxActorSignals = cache.getEntry("otx").data?.actorSignals;
  const newsItems = getTaggedNewsItems({
    newsItems: cache.getEntry("news").data?.items,
    attackData,
    ransomwareCampaigns,
    threatFeedIocs: threatFeedIocs(),
    kevEntries,
    epssScores: cache.getEntry("epss").data,
  });

  const actors = buildTopThreatActorsToday({ ransomwareCampaigns, otxActorSignals, newsItems, attackData });
  res.json({ actors });
});

// --- GitHub Intel (repo discovery, classification, extraction, correlation, scoring) ---
router.get("/dashboard/github-intel/stats", (_req, res) => {
  const repos = getAllGithubRepos();
  const enriched = repos.filter((r) => r.lastEnrichedAt);

  const categoryCounts = {};
  for (const repo of enriched) {
    for (const c of repo.categories ?? []) categoryCounts[c.category] = (categoryCounts[c.category] ?? 0) + 1;
  }

  const topCves = computeTopCves(repos, 10);

  res.json({
    totalRepos: repos.length,
    enrichedRepos: enriched.length,
    pendingEnrichment: repos.length - enriched.length,
    categoryCounts,
    topCves,
  });
});

router.get("/dashboard/github-intel", (req, res) => {
  const { category, minScore = "0" } = req.query;
  let repos = getAllGithubRepos();

  if (category) repos = repos.filter((r) => (r.categories ?? []).some((c) => c.category === category));
  if (Number(minScore) > 0) repos = repos.filter((r) => (r.threatScore?.score ?? 0) >= Number(minScore));

  repos.sort((a, b) => (b.threatScore?.score ?? -1) - (a.threatScore?.score ?? -1));

  const summaries = repos.map((r) => ({
    fullName: r.fullName,
    url: r.url,
    description: r.description,
    stars: r.stars,
    forks: r.forks,
    lastCommitDate: r.lastCommitDate,
    topics: r.topics,
    discoveredVia: r.discoveredVia,
    categories: r.categories ?? [],
    threatScore: r.threatScore?.score ?? null,
    cveCount: r.extracted?.cveIds?.length ?? 0,
    matchedFeedCount: r.correlation?.matchedFeeds ?? 0,
    lastEnrichedAt: r.lastEnrichedAt ?? null,
  }));

  res.json({ repos: summaries.slice(0, 200), totalCount: summaries.length });
});

router.get("/dashboard/github-intel/:owner/:repo", (req, res) => {
  const fullName = `${req.params.owner}/${req.params.repo}`;
  const repo = getAllGithubRepos().find((r) => r.fullName === fullName);
  if (!repo) return res.status(404).json({ error: `No discovered repo found for "${fullName}"` });
  res.json(repo);
});

// Lookup-only sources have no bulk feed/cache entry of their own -- they only
// ever run live from IOC Search -- so "health" for them just means whether a
// key is configured, not a sync freshness timestamp.
const LOOKUP_ONLY_SOURCES = [
  { key: "virustotal", label: "VirusTotal (IOC Search)", envVar: "VIRUSTOTAL_API_KEY" },
  { key: "greynoise", label: "GreyNoise Community (IOC Search)", envVar: "GREYNOISE_API_KEY" },
  { key: "shodan", label: "Shodan (IOC Search)", envVar: "SHODAN_API_KEY" },
  { key: "hybrid-analysis", label: "Hybrid Analysis (IOC Search)", envVar: "HYBRID_ANALYSIS_API_KEY" },
  { key: "leakix", label: "LeakIX (IOC Search)", envVar: "LEAKIX_API_KEY" },
];

// --- Feed health / last-synchronized -------------------------------------
function buildHealth() {
  const health = connectors
    .filter((c) => c.id !== "news") // news is broken out per-sub-source below
    .map((connector) => {
      const entry = cache.getEntry(connector.id);
      return {
        key: connector.id,
        label: connector.label,
        online: !entry.error,
        lastSynchronized: entry.updatedAt,
        error: entry.error ?? undefined,
      };
    });

  const newsEntry = cache.getEntry("news");
  const newsSources = newsEntry.data?.sources ?? {};
  for (const [label, status] of Object.entries(newsSources)) {
    health.push({
      key: `news-${label.toLowerCase().replace(/\s+/g, "-")}`,
      label,
      online: status.ok,
      lastSynchronized: newsEntry.updatedAt,
      error: status.error,
    });
  }

  for (const { key, label, envVar } of LOOKUP_ONLY_SOURCES) {
    const configured = Boolean(process.env[envVar]);
    health.push({
      key,
      label,
      online: configured,
      lastSynchronized: null,
      error: configured ? undefined : `Not configured -- set ${envVar} to enable`,
    });
  }

  return health;
}

router.get("/dashboard/health", (_req, res) => {
  const health = buildHealth();
  res.json({ sources: health, onlineCount: health.filter((h) => h.online).length, totalCount: health.length });
});

// --- IOC Search: live fan-out across OTX/AbuseIPDB/Pulsedive/VirusTotal/GreyNoise/Shodan/Hybrid Analysis/LeakIX ---
// Every free-tier lookup is wrapped in throttleAndCache: a short (10 min)
// per-indicator cache plus a minimum spacing between live calls to that
// source, so repeat/rapid searches can't blow through e.g. VirusTotal's
// 4-req/min free-tier quota.
const IOC_LOOKUPS = {
  ip: [
    checkOtx,
    checkAbuseIpdb,
    throttleAndCache("Pulsedive", 3_000, checkPulsedive),
    throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
    throttleAndCache("GreyNoise", 2_000, checkGreyNoise),
    throttleAndCache("Shodan", 1_000, checkShodan),
    throttleAndCache("LeakIX", 5_000, checkLeakix),
  ],
  domain: [
    checkOtx,
    throttleAndCache("Pulsedive", 3_000, checkPulsedive),
    throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
    throttleAndCache("LeakIX", 5_000, checkLeakix),
  ],
  url: [checkOtx, throttleAndCache("Pulsedive", 3_000, checkPulsedive), throttleAndCache("VirusTotal", 15_000, checkVirusTotal)],
  hash: [checkOtx, throttleAndCache("VirusTotal", 15_000, checkVirusTotal), throttleAndCache("Hybrid Analysis", 5_000, checkHybridAnalysis)],
};

router.get("/ioc-search", async (req, res) => {
  const { type, value } = req.query;
  if (!type || !value) return res.status(400).json({ error: "type and value query params are required" });

  const lookups = IOC_LOOKUPS[type];
  if (!lookups) return res.status(400).json({ error: `Unsupported indicator type "${type}"` });

  const settled = await Promise.allSettled(lookups.map((fn) => fn(type, value)));
  const results = [];
  const notConfigured = [];
  const rateLimited = [];
  for (const outcome of settled) {
    if (outcome.status === "fulfilled") {
      results.push(outcome.value);
    } else if (outcome.reason?.status === 401) {
      notConfigured.push(outcome.reason.source);
    } else if (outcome.reason?.status === 429) {
      rateLimited.push(outcome.reason.source);
    }
  }

  const maliciousVotes = results.filter((r) => r.verdict === "malicious").length;
  const suspiciousVotes = results.filter((r) => r.verdict === "suspicious").length;
  const correlatedVerdict = maliciousVotes >= 2 ? "malicious" : maliciousVotes >= 1 || suspiciousVotes >= 1 ? "suspicious" : results.length > 0 ? "clean" : "unknown";

  res.json({ indicator: value, type, correlatedVerdict, results, notConfigured, rateLimited });
});
