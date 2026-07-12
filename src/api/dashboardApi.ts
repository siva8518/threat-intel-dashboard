import { fetchJson } from "@/lib/http";
import type {
  AttackTacticHeatmapCell,
  AttackTechnique,
  CampaignIntelligenceEntity,
  CorrelationCard,
  CveProfile,
  CveProgramActivity,
  CveRecord,
  CveSeverityDistribution,
  DailySummary,
  ExecutiveSummary,
  ExploitIntelligence,
  GeoTargeting,
  GithubIntelStats,
  GithubRepoDetail,
  GithubRepoSummary,
  IocRecord,
  IocSearchIndicatorType,
  IocSearchResult,
  KevEntry,
  MalwareIntelligenceEntity,
  MalwareProfile,
  NewsItem,
  RansomwareCampaign,
  SourceHealth,
  ThreatActor,
  ThreatActorIntelligenceEntity,
  ThreatActorSummary,
  ThreatTimelineEvent,
  TodaySecurityEvents,
  TrendingMalwareEntry,
  VulnCheckKevCatalog,
} from "@/types/threat-intel";

// Thin client over the backend aggregation service (server/routes/dashboard.js).
// All parsing, normalization and correlation now happens server-side -- this
// file just calls already-normalized JSON endpoints. Replaces what used to be
// eight separate per-source files (cisaKev.ts, nvd.ts, urlhaus.ts, ...).

export interface CveQueryParams {
  keyword?: string;
  severity?: string;
  page?: number;
  pageSize?: number;
}

export interface CveQueryResult {
  totalResults: number;
  records: CveRecord[];
}

export async function fetchCves(params: CveQueryParams): Promise<CveQueryResult> {
  const search = new URLSearchParams();
  if (params.keyword) search.set("keyword", params.keyword);
  if (params.severity) search.set("severity", params.severity);
  search.set("page", String(params.page ?? 0));
  search.set("pageSize", String(params.pageSize ?? 20));
  return fetchJson(`/api/dashboard/cves?${search.toString()}`, { source: "Dashboard API" });
}

export async function fetchCveProgramActivity(): Promise<CveProgramActivity> {
  return fetchJson("/api/dashboard/cve-program-activity", { source: "Dashboard API" });
}

export async function fetchCveSeverityDistribution(): Promise<CveSeverityDistribution> {
  return fetchJson("/api/dashboard/cve-severity-distribution", { source: "Dashboard API" });
}

export interface KevCatalog {
  count: number;
  dateReleased: string;
  entries: KevEntry[];
}

export async function fetchKev(): Promise<KevCatalog> {
  return fetchJson("/api/dashboard/kev", { source: "Dashboard API" });
}

export async function fetchVulnCheckKev(): Promise<VulnCheckKevCatalog> {
  return fetchJson("/api/dashboard/vulncheck-kev", { source: "Dashboard API" });
}

export async function fetchExploits(): Promise<ExploitIntelligence> {
  return fetchJson("/api/dashboard/exploits", { source: "Dashboard API" });
}

export async function fetchThreatFeed(): Promise<{ iocs: IocRecord[] }> {
  return fetchJson("/api/dashboard/threat-feed", { source: "Dashboard API" });
}

export async function fetchTrendingMalware(): Promise<TrendingMalwareEntry[]> {
  return fetchJson("/api/dashboard/malware-trending", { source: "Dashboard API" });
}

export async function fetchMalwareIntelligence(): Promise<{ entities: MalwareIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/malware-intelligence", { source: "Dashboard API" });
}

export async function fetchThreatActorIntelligence(): Promise<{ entities: ThreatActorIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/threat-actor-intelligence", { source: "Dashboard API" });
}

export async function fetchCampaignIntelligence(): Promise<{ entities: CampaignIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/campaign-intelligence", { source: "Dashboard API" });
}

export async function fetchAttackTechniques(): Promise<AttackTechnique[]> {
  return fetchJson("/api/dashboard/attack-techniques", { source: "Dashboard API" });
}

export async function fetchAttackTacticHeatmap(): Promise<AttackTacticHeatmapCell[]> {
  return fetchJson("/api/dashboard/attack-tactic-heatmap", { source: "Dashboard API" });
}

export async function fetchRansomwareCampaigns(): Promise<{ campaigns: RansomwareCampaign[] }> {
  return fetchJson("/api/dashboard/ransomware", { source: "Dashboard API" });
}

export async function fetchThreatActors(): Promise<ThreatActor[]> {
  return fetchJson("/api/dashboard/threat-actors", { source: "Dashboard API" });
}

export async function fetchNews(): Promise<{ items: NewsItem[] }> {
  return fetchJson("/api/dashboard/news", { source: "Dashboard API" });
}

export interface SummaryPayload {
  criticalCves30d: number | null;
  newCves24h: number | null;
  knownExploitedVulnerabilities: number | null;
  maliciousUrls: number;
  sourcesOnline: number;
  sourcesTotal: number;
}

export async function fetchSummary(): Promise<SummaryPayload> {
  return fetchJson("/api/dashboard/summary", { source: "Dashboard API" });
}

export async function fetchExecutiveSummary(): Promise<ExecutiveSummary> {
  return fetchJson("/api/dashboard/executive-summary", { source: "Dashboard API" });
}

export async function fetchGeoTargeting(): Promise<GeoTargeting> {
  return fetchJson("/api/dashboard/geo-targeting", { source: "Dashboard API" });
}

export async function fetchCorrelationEngine(): Promise<{ cards: CorrelationCard[] }> {
  return fetchJson("/api/dashboard/correlation-engine", { source: "Dashboard API" });
}

export async function fetchTodaySecurityEvents(): Promise<TodaySecurityEvents> {
  return fetchJson("/api/dashboard/today-events", { source: "Dashboard API" });
}

export async function fetchDailySummary(): Promise<DailySummary> {
  return fetchJson("/api/dashboard/daily-summary", { source: "Dashboard API" });
}

export async function fetchThreatTimeline(days: number): Promise<{ events: ThreatTimelineEvent[]; days: number }> {
  return fetchJson(`/api/dashboard/threat-timeline?days=${days}`, { source: "Dashboard API" });
}

export async function fetchCveById(cveId: string): Promise<CveRecord> {
  return fetchJson(`/api/dashboard/cve/${encodeURIComponent(cveId)}`, { source: "Dashboard API" });
}

export async function fetchSourcesHealth(): Promise<{ sources: SourceHealth[]; onlineCount: number; totalCount: number }> {
  return fetchJson("/api/dashboard/health", { source: "Dashboard API" });
}

export async function searchIoc(type: IocSearchIndicatorType, value: string): Promise<IocSearchResult> {
  const search = new URLSearchParams({ type, value });
  return fetchJson(`/api/ioc-search?${search.toString()}`, { source: "IOC Search" });
}

// The full-profile (fetchThreatActorProfile) and list (fetchThreatActorList)
// endpoints are still live on the backend (used by the MCP server's
// get_threat_actor_profile tool, see server/mcpServer.js) but no longer have
// a frontend consumer since the Threat Actor Profiles tab was removed in
// favor of Threat Actor Intelligence -- only the search endpoint (used by
// the platform search palette, see CommandPalette.tsx) is still called here.
export async function searchThreatActorProfiles(query: string): Promise<{ actors: ThreatActorSummary[] }> {
  return fetchJson(`/api/dashboard/threat-actor-profiles/search?q=${encodeURIComponent(query)}`, { source: "Dashboard API" });
}

export interface GithubIntelListParams {
  category?: string;
  minScore?: number;
}

export async function fetchGithubIntelList(params: GithubIntelListParams = {}): Promise<{ repos: GithubRepoSummary[]; totalCount: number }> {
  const search = new URLSearchParams();
  if (params.category) search.set("category", params.category);
  if (params.minScore) search.set("minScore", String(params.minScore));
  const query = search.toString();
  return fetchJson(`/api/dashboard/github-intel${query ? `?${query}` : ""}`, { source: "Dashboard API" });
}

export async function fetchGithubIntelStats(): Promise<GithubIntelStats> {
  return fetchJson("/api/dashboard/github-intel/stats", { source: "Dashboard API" });
}

export async function fetchGithubRepoDetail(fullName: string): Promise<GithubRepoDetail> {
  return fetchJson(`/api/dashboard/github-intel/${fullName}`, { source: "Dashboard API" });
}

export async function fetchCveProfile(cveId: string): Promise<CveProfile> {
  return fetchJson(`/api/dashboard/cve-profile/${encodeURIComponent(cveId)}`, { source: "Dashboard API" });
}

export async function fetchMalwareProfile(family: string): Promise<MalwareProfile> {
  return fetchJson(`/api/dashboard/malware-profile/${encodeURIComponent(family)}`, { source: "Dashboard API" });
}
