import { fetchJson } from "@/lib/http";
import type {
  AiThreatSummaryReport,
  ReportSectionProvenanceMap,
  AttackTacticHeatmapCell,
  AttackTechnique,
  CampaignIntelligenceEntity,
  DarkWebIntelligenceEntity,
  WatchlistKeyword,
  FlashReport,
  CveProfile,
  CveProgramActivity,
  CveRecord,
  CveSeverityDistribution,
  DetectionBacklogItem,
  DetectionBacklogStatus,
  DraftArtifactSet,
  EmergingThreatsRanking,
  ExecutiveSummary,
  ExploitIntelligence,
  GeoTargeting,
  GithubIntelStats,
  GithubRepoDetail,
  GithubRepoSummary,
  HuntingQueryItem,
  IndustryBriefing,
  IndustryName,
  IocRecord,
  InvestigationResult,
  AiInvestigationReport,
  GraphNodeType,
  GraphNodeResult,
  GraphEdge,
  GraphNode,
  GraphInsights,
  CorrelationSummary,
  ShouldICareAssessment,
  KevEntry,
  MalwareIntelligenceEntity,
  AiProviderHealth,
  AiUsageRollup,
  MalwareProfile,
  NewsItem,
  RansomwareCampaign,
  RemediationQueueItem,
  RemediationStatus,
  SourceHealth,
  ThreatActor,
  ThreatActorIntelligenceEntity,
  ThreatActorSummary,
  ThreatTimelineEvent,
  ToolIntelligenceEntity,
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
  /** Present only when NVD's own cache is unavailable at a cold start -- the list came from CVE Program + CIRCL instead. See server/lookups/cveFallback.js. */
  fallbackSource?: string;
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

export async function fetchToolIntelligence(): Promise<{ entities: ToolIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/tool-intelligence", { source: "Dashboard API" });
}

export async function fetchThreatActorIntelligence(): Promise<{ entities: ThreatActorIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/threat-actor-intelligence", { source: "Dashboard API" });
}

export async function fetchCampaignIntelligence(): Promise<{ entities: CampaignIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/campaign-intelligence", { source: "Dashboard API" });
}

export async function fetchDarkWebIntelligence(): Promise<{ entities: DarkWebIntelligenceEntity[] }> {
  return fetchJson("/api/dashboard/darkweb-intelligence", { source: "Dashboard API" });
}

export async function fetchAiThreatSummaries(): Promise<{ reports: AiThreatSummaryReport[] }> {
  return fetchJson("/api/dashboard/ai-summaries", { source: "Dashboard API" });
}

export async function fetchAiSummaryProvenance(): Promise<ReportSectionProvenanceMap> {
  return fetchJson("/api/dashboard/ai-summaries-provenance", { source: "Dashboard API" });
}

export async function fetchEmergingThreatsRanking(): Promise<EmergingThreatsRanking> {
  return fetchJson("/api/dashboard/emerging-threats-ranking", { source: "Dashboard API" });
}

export async function fetchIndustryBriefing(industry: IndustryName): Promise<IndustryBriefing> {
  return fetchJson(`/api/dashboard/industry-briefing?industry=${encodeURIComponent(industry)}`, { source: "Dashboard API" });
}

export async function fetchWatchlist(): Promise<{ keywords: WatchlistKeyword[] }> {
  return fetchJson("/api/dashboard/watchlist", { source: "Dashboard API" });
}

export async function addWatchlistKeyword(label: string): Promise<{ keyword: WatchlistKeyword }> {
  return fetchJson("/api/dashboard/watchlist", {
    source: "Dashboard API",
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label }),
  });
}

export async function removeWatchlistKeyword(id: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/dashboard/watchlist/${encodeURIComponent(id)}`, { source: "Dashboard API", method: "DELETE" });
}

export async function fetchFlashReports(): Promise<{ reports: FlashReport[]; unreadCount: number }> {
  return fetchJson("/api/dashboard/flash-reports", { source: "Dashboard API" });
}

export async function markFlashReportRead(id: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/dashboard/flash-reports/${encodeURIComponent(id)}/read`, { source: "Dashboard API", method: "POST" });
}

export async function markAllFlashReportsRead(): Promise<{ ok: boolean }> {
  return fetchJson("/api/dashboard/flash-reports/read-all", { source: "Dashboard API", method: "POST" });
}

export async function fetchAttackTechniques(days?: number | null): Promise<AttackTechnique[]> {
  const qs = days ? `?days=${days}` : "";
  return fetchJson(`/api/dashboard/attack-techniques${qs}`, { source: "Dashboard API" });
}

export async function fetchAttackTacticHeatmap(): Promise<AttackTacticHeatmapCell[]> {
  return fetchJson("/api/dashboard/attack-tactic-heatmap", { source: "Dashboard API" });
}

export async function fetchRansomwareCampaigns(): Promise<{ campaigns: RansomwareCampaign[] }> {
  return fetchJson("/api/dashboard/ransomware", { source: "Dashboard API" });
}

export async function fetchThreatActors(days?: number | null): Promise<ThreatActor[]> {
  const qs = days ? `?days=${days}` : "";
  return fetchJson(`/api/dashboard/threat-actors${qs}`, { source: "Dashboard API" });
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

export async function fetchTodaySecurityEvents(): Promise<TodaySecurityEvents> {
  return fetchJson("/api/dashboard/today-events", { source: "Dashboard API" });
}

export async function fetchThreatTimeline(days: number): Promise<{ events: ThreatTimelineEvent[]; days: number }> {
  return fetchJson(`/api/dashboard/threat-timeline?days=${days}`, { source: "Dashboard API" });
}

export async function fetchCveById(cveId: string): Promise<CveRecord> {
  return fetchJson(`/api/dashboard/cve/${encodeURIComponent(cveId)}`, { source: "Dashboard API" });
}

export async function fetchRemediationQueue(): Promise<{ items: RemediationQueueItem[]; ready: boolean }> {
  return fetchJson("/api/dashboard/remediation-queue", { source: "Dashboard API" });
}

export async function setRemediationStatus(
  cveId: string,
  status: RemediationStatus,
  note: string | null,
): Promise<{ cveId: string; status: RemediationStatus; note: string | null; updatedAt: string }> {
  return fetchJson(`/api/dashboard/remediation/${encodeURIComponent(cveId)}`, {
    source: "Dashboard API",
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, note }),
  });
}

export async function clearRemediationStatus(cveId: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/dashboard/remediation/${encodeURIComponent(cveId)}`, { source: "Dashboard API", method: "DELETE" });
}

export async function fetchHuntingLibrary(): Promise<{ items: HuntingQueryItem[] }> {
  return fetchJson("/api/dashboard/hunting-library", { source: "Dashboard API" });
}

export async function fetchDetectionBacklog(): Promise<{ items: DetectionBacklogItem[] }> {
  return fetchJson("/api/dashboard/detection-backlog", { source: "Dashboard API" });
}

export async function setDetectionBacklogStatus(
  id: string,
  status: DetectionBacklogStatus,
  note: string | null,
): Promise<{ id: string; status: DetectionBacklogStatus; note: string | null; updatedAt: string }> {
  return fetchJson(`/api/dashboard/detection-backlog/${encodeURIComponent(id)}`, {
    source: "Dashboard API",
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, note }),
  });
}

export async function clearDetectionBacklogStatus(id: string): Promise<{ ok: boolean }> {
  return fetchJson(`/api/dashboard/detection-backlog/${encodeURIComponent(id)}`, { source: "Dashboard API", method: "DELETE" });
}

export async function draftDetectionBacklogArtifacts(
  id: string,
): Promise<{ id: string; status: DetectionBacklogStatus; note: string | null; updatedAt: string; draftArtifacts: DraftArtifactSet }> {
  // 12 artifacts assessed in one completion is a much larger generation than
  // the single-rule version this replaced -- a longer timeout than the
  // default 60s gives server/groqClient.js's own 60s request timeout room to
  // fire and surface its real error first, rather than this racing it with
  // a generic "Dashboard API timed out" message.
  return fetchJson(`/api/dashboard/detection-backlog/${encodeURIComponent(id)}/draft-artifacts`, { source: "Dashboard API", method: "POST", timeoutMs: 90_000 });
}

export async function fetchSourcesHealth(): Promise<{ sources: SourceHealth[]; onlineCount: number; totalCount: number }> {
  return fetchJson("/api/dashboard/health", { source: "Dashboard API" });
}

export async function fetchAiProviderHealth(): Promise<{ providers: AiProviderHealth[] }> {
  return fetchJson("/api/dashboard/ai-provider-health", { source: "Dashboard API" });
}

export async function fetchAiUsage(): Promise<AiUsageRollup> {
  return fetchJson("/api/dashboard/ai-usage", { source: "Dashboard API" });
}

/** Auto-detects the indicator type server-side and returns the full Universal Overview + type-specific module data -- see server/investigation/index.js. */
export async function investigate(query: string): Promise<InvestigationResult> {
  return fetchJson(`/api/investigate?query=${encodeURIComponent(query)}`, { source: "Intelligence Investigation Console" });
}

/** On-demand only -- fired by the "Generate AI Report" button, never automatically on search. Longer timeout since this is a real LLM call, same reasoning as draftDetectionBacklogArtifacts above. */
export async function generateInvestigationAiReport(query: string): Promise<AiInvestigationReport> {
  return fetchJson("/api/investigate/ai-report", {
    source: "Intelligence Investigation Console",
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
    timeoutMs: 90_000,
  });
}

/** One node of the Investigation Graph -- see server/investigation/investigationGraph.js. Pure correlation, no AI call, cheap to re-run on every expand click. */
export async function fetchInvestigationGraphNode(type: GraphNodeType, key: string): Promise<GraphNodeResult> {
  return fetchJson(`/api/dashboard/investigation-graph?type=${encodeURIComponent(type)}&key=${encodeURIComponent(key)}`, { source: "Investigation Graph" });
}

/** Fired automatically once a Workspace search's relationships finish loading (see useInvestigationWorkspace.ts) -- posts the graph node/edges the client already has in memory rather than re-fetching them server-side. Real LLM call, same generous timeout as generateInvestigationAiReport. */
export async function generateGraphInsights(payload: {
  node: GraphNode;
  edges: GraphEdge[];
  unavailableRelationships: Array<{ relationshipType: string; reason: string }>;
  overview: InvestigationResult["overview"] | null;
}): Promise<GraphInsights> {
  return fetchJson("/api/dashboard/investigation-graph/insights", {
    source: "AI Investigation Summary",
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    timeoutMs: 90_000,
  });
}

/** Fired automatically alongside generateGraphInsights above (see useInvestigationWorkspace.ts) -- posts the full already-fetched InvestigationResult so the server never re-runs the live-lookup fan-out. Reasons across the whole unified result, not just the graph's direct edges. */
export async function generateCorrelationSummary(result: InvestigationResult): Promise<CorrelationSummary> {
  return fetchJson("/api/dashboard/investigation/correlation-summary", {
    source: "AI Correlation Summary",
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(result),
    timeoutMs: 90_000,
  });
}

/** Fired automatically alongside generateCorrelationSummary above (see useInvestigationWorkspace.ts) -- the human-centric "Should I Care?" assessment, see server/investigation/shouldICare.js. */
export async function generateShouldICare(result: InvestigationResult): Promise<ShouldICareAssessment> {
  return fetchJson("/api/dashboard/investigation/should-i-care", {
    source: "Should I Care?",
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(result),
    timeoutMs: 90_000,
  });
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

export async function fetchGithubIntelStats(days?: number | null): Promise<GithubIntelStats> {
  const qs = days ? `?days=${days}` : "";
  return fetchJson(`/api/dashboard/github-intel/stats${qs}`, { source: "Dashboard API" });
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
