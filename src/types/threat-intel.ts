export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface CveRecord {
  id: string;
  severity: Severity;
  cvssScore: number | null;
  vendor: string;
  product: string;
  publishedDate: string; // ISO string
  description: string;
  knownExploited: boolean;
  epssScore: number | null; // 0-1 probability of exploitation in the next 30 days
  epssPercentile: number | null; // 0-1 percentile rank vs all scored CVEs
  sourceUrl: string;
}

export interface KevEntry {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string; // ISO date
  dueDate: string;
  requiredAction: string;
  ransomwareUse: boolean;
}

export type IocType = "ip" | "domain" | "url" | "hash" | "unknown";

export interface IocRecord {
  id: string;
  indicator: string;
  indicatorType: IocType;
  malwareFamily: string;
  threatType: string;
  firstSeen: string; // ISO string
  source: string; // primary/first-seen source label
  sources: string[]; // every source this indicator was seen in, after dedup
}

export type NewsSeverity = "critical" | "high" | "medium" | "low";

export interface NewsTags {
  cveIds: string[];
  actors: string[];
  malware: string[];
  industries: string[];
  countries: string[];
}

export interface NewsItem {
  id: string;
  title: string;
  link: string;
  source: string;
  publishedDate: string; // ISO string
  tags: NewsTags;
  severity: NewsSeverity;
  isBreaking: boolean;
}

export interface AttackTechnique {
  id: string; // e.g. "T1566.001"
  name: string;
  tactic: string;
  url: string;
  observedCount?: number;
}

export interface TrendingMalwareEntry {
  family: string;
  count: number;
  sources: string[];
  techniques: AttackTechnique[];
}

export interface RansomwareCampaign {
  id: string;
  group: string;
  victim: string;
  sector: string;
  country: string;
  discoveredDate: string;
  sourceUrl: string | null;
  industry: string; // e.g. "LSHC", "TMT", "FSI", "Consumer", "Other" -- same bucket as ExecutiveSummary.industriesTargeted
}

export interface ThreatActor {
  name: string;
  type: "ransomware" | "otx-tagged";
  campaignCount: number;
  lastActivity: string;
}

export interface GeoTargetingCountry {
  countryCode: string; // ISO 3166-1 alpha-2, e.g. "US"
  numericId: string; // ISO 3166-1 numeric, matches the world-atlas topojson id
  count: number;
  topActors: Array<{ name: string; count: number }>;
}

export interface ThreatActorSummary {
  attackId: string; // ATT&CK Group id, e.g. "G0032"
  name: string;
  aliases: string[];
  country: string | null;
}

export interface RelatedSoftware {
  name: string;
  aliases: string[];
  url: string;
}

export interface RelatedCampaign {
  source: "MITRE ATT&CK" | "ransomware.live";
  name: string;
  description: string;
  date: string | null;
  url: string | null;
}

export interface RelatedCve {
  id: string;
  description: string;
  severity: Severity;
  publishedDate: string;
  sourceUrl: string;
}

export interface RelatedMalwareSighting {
  indicator: string;
  indicatorType: IocType;
  malwareFamily: string;
  firstSeen: string;
  sources: string[];
}

export interface TimelineEvent {
  date: string;
  label: string;
  url: string | null;
}

export interface ThreatActorProfile {
  attackId: string;
  name: string;
  aliases: string[];
  description: string;
  url: string;
  country: string | null;
  motivations: string[];
  activeSince: string | null;
  targetIndustries: string[];
  malwareUsed: RelatedSoftware[];
  toolsUsed: RelatedSoftware[];
  malpediaMalware: RelatedSoftware[];
  techniques: AttackTechnique[];
  relatedCampaigns: RelatedCampaign[];
  relatedCves: RelatedCve[];
  relatedMalware: RelatedMalwareSighting[];
  recentNews: NewsItem[];
  timeline: TimelineEvent[];
}

export type IocSearchIndicatorType = "ip" | "domain" | "url" | "hash";

export interface IocLookupResult {
  source: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  [key: string]: unknown;
}

export interface IocSearchResult {
  indicator: string;
  type: IocSearchIndicatorType;
  correlatedVerdict: "malicious" | "suspicious" | "clean" | "unknown";
  results: IocLookupResult[];
  notConfigured: string[];
  rateLimited: string[];
}

export interface CveProgramEntry {
  cveId: string;
  dateUpdated: string;
  url: string;
}

export interface CveProgramActivity {
  fetchedAt: string | null;
  newCves: CveProgramEntry[];
  updatedCves: CveProgramEntry[];
}

export interface GithubRepoCategory {
  category: string;
  confidence: number; // 0-1
}

export interface GithubRepoSummary {
  fullName: string;
  url: string;
  description: string | null;
  stars: number;
  forks: number;
  lastCommitDate: string;
  topics: string[];
  discoveredVia: string;
  categories: GithubRepoCategory[];
  threatScore: number | null;
  cveCount: number;
  matchedFeedCount: number;
  lastEnrichedAt: string | null;
}

export interface GithubExtractedEntities {
  cveIds: string[];
  sha256: string[];
  sha1: string[];
  md5: string[];
  ipv4: string[];
  ipv6: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  yaraRuleNames: string[];
  sigmaRuleIds: string[];
  attackTechniques: string[]; // e.g. "T1059.001"
  attackTactics: string[];
  threatActorNames: string[];
  malwareFamilies: string[];
}

export interface GithubIocCorrelationMatch {
  indicator: string;
  indicatorType: IocType;
  malwareFamily: string;
  sources: string[];
}

export interface GithubIocCorrelation {
  matches: GithubIocCorrelationMatch[];
  matchedFeeds: number;
  feedsChecked: number;
}

export interface GithubCveEnrichment {
  id: string;
  description: string | null;
  severity: Severity;
  cvssScore: number | null;
  publishedDate: string | null;
  sourceUrl: string;
  knownExploited: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
}

export interface ThreatScoreBreakdownEntry {
  signal: string;
  normalized: number;
  weight: number;
  contribution: number;
}

export interface GithubRepoDetail {
  id: number;
  fullName: string;
  url: string;
  description: string | null;
  stars: number;
  forks: number;
  lastCommitDate: string;
  topics: string[];
  defaultBranch: string;
  discoveredVia: string;
  categories: GithubRepoCategory[];
  extracted: GithubExtractedEntities;
  correlation: GithubIocCorrelation;
  cveEnrichment: GithubCveEnrichment[];
  threatScore: { score: number; breakdown: ThreatScoreBreakdownEntry[] } | null;
  lastEnrichedAt: string | null;
  enrichmentError?: string;
}

export interface GithubIntelStats {
  totalRepos: number;
  enrichedRepos: number;
  pendingEnrichment: number;
  categoryCounts: Record<string, number>;
  topCves: Array<{ cveId: string; repoCount: number }>;
}

export interface SourceHealth {
  key: string;
  label: string;
  online: boolean;
  lastSynchronized: number | null; // epoch ms
  error?: string;
}

export interface MalwareProfile {
  family: string;
  attackReference: { name: string; type: "malware" | "tool"; url: string } | null;
  iocs: IocRecord[];
  techniques: AttackTechnique[];
  actors: Array<{ attackId: string; name: string; country: string | null; url: string }>;
  news: NewsItem[];
}

export interface CveProfileGithubPoc {
  fullName: string;
  url: string;
  stars: number;
  threatScore: number | null;
}

export type ThreatLevel = "Low" | "Elevated" | "High" | "Critical";

export interface ThreatScoreSignal {
  signal: "criticalCves" | "kevActivity" | "iocVolume" | "ransomware" | "malwareConcentration";
  normalized: number; // 0-1
  weight: number; // 0-1, sums to 1 across all signals
  contribution: number; // 0-100, this signal's share of the final score
}

export interface MostExploitedCve {
  cveId: string;
  knownExploited: boolean;
  repoCount: number;
  reason: string;
}

export interface ExecutiveSummaryActor {
  name: string;
  type: "ransomware" | "otx-tagged";
  campaignCount: number;
  lastActivity: string;
}

export interface IndustryTarget {
  industry: string;
  count: number;
}

export interface ExecutiveSummary {
  score: number; // 0-100
  level: ThreatLevel;
  breakdown: ThreatScoreSignal[];
  generatedAt: string;
  mostActiveActor: ExecutiveSummaryActor | null;
  mostActiveMalware: TrendingMalwareEntry | null;
  mostExploitedCve: MostExploitedCve | null;
  industriesTargeted: IndustryTarget[];
  countriesUnderAttack: GeoTargetingCountry[];
  totalActiveCampaigns: number;
}

export interface CveProfile {
  cveId: string;
  relatedActors: Array<{ attackId: string; name: string; country: string | null; url: string }>;
  relatedMalware: string[];
  relatedCampaigns: Array<{ name: string; description: string; date: string | null; url: string | null }>;
  relatedTechniques: AttackTechnique[];
  relatedIocs: IocRecord[];
  githubPocs: CveProfileGithubPoc[];
  relatedNews: NewsItem[];
}

export interface CorrelationCard {
  malware: string[];
  actors: string[];
  cves: Array<{ id: string; knownExploited: boolean }>;
  techniques: AttackTechnique[];
  iocs: Array<{ indicatorType: IocType; indicator: string }>;
  githubRepos: Array<{ fullName: string; url: string; stars: number }>;
  ransomwareCampaigns: RansomwareCampaign[];
  entityTypeCount: number;
  recordCount: number;
  totalIocCount: number;
}

export interface TodaySecurityEvents {
  criticalKev: number;
  activeExploitCampaigns: number;
  newRansomwareVictims: number;
  newMalwareSamples: number;
  githubExploits: number;
  newIocs: number;
  generatedAt: string;
}

export type DailySummaryAction =
  | { type: "tab"; tab: "cves" | "threat-actors" | "threat-feed" }
  | { type: "malware"; family: string }
  | { type: "news-source"; source: string };

export interface DailySummaryBullet {
  text: string;
  action: DailySummaryAction | null;
}

export interface DailySummary {
  bullets: DailySummaryBullet[];
  readingTimeSeconds: number;
  generatedAt: string;
}

export type ActorTrend = "up" | "down" | "steady";

export interface TopThreatActor {
  rank: number;
  name: string;
  score: number;
  trend: ActorTrend;
}

export interface TopExploitedCve {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  sourceUrl: string;
  ransomwareUse: boolean;
  actors: string[];
}
