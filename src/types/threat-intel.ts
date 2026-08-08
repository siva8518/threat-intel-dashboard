export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

/** CVEs published in the last 30 days, bucketed by CVSS v3 severity -- see server/connectors/nvd.js. */
export interface CveSeverityDistribution {
  /** False only until the NVD connector's first sync since server boot completes -- see server/routes/dashboard.js. Distinct from all-zero counts, which can be genuine. */
  ready: boolean;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

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

export type RemediationStatus = "pending" | "patched" | "mitigated" | "risk_accepted";

/**
 * One CVE in the Remediation Tracker's prioritized queue -- everything from
 * CveRecord plus a deterministic urgencyScore (KEV+EPSS+CVSS, see
 * server/remediationQueue.js), the VM team's own tracked status/note (this
 * app's only source of truth for that -- nothing external reports it), and
 * patch guidance pulled from AI Summarization when that article's already
 * been analyzed.
 */
export interface RemediationQueueItem extends CveRecord {
  urgencyScore: number;
  status: RemediationStatus;
  note: string | null;
  statusUpdatedAt: string | null;
  patchInfo: AiThreatSummaryVulnerabilityManagement | null;
}

export type HuntingQueryPlatform =
  | "defenderXdrKql"
  | "sentinelKql"
  | "splunkSpl"
  | "elastic"
  | "sigma"
  | "yara"
  | "crowdstrikeFalcon"
  | "carbonBlack";

/** One hunting query, either flattened out of an AI Summarization report's threatHuntingOpportunities, or derived deterministically from a Malware/Threat Actor Intelligence entity's own live indicators/detection-rule matches (see server/huntingLibrary.js) -- traced back to the article/rule/CVEs/malware/actors it came from, so a hit in the library is never just a bare query with no context. */
export interface HuntingQueryItem {
  id: string;
  platform: HuntingQueryPlatform;
  platformLabel: string;
  query: string;
  source: "ai-report" | "entity";
  reportId: string;
  articleTitle: string;
  articleLink: string;
  articleSource: string;
  generatedAt: string;
  severity: Severity;
  cveIds: string[];
  malware: string[];
  threatActors: string[];
}

// Matches server/detectionBacklog.js's CATEGORY_LABELS keys exactly: the
// first three are AI Summarization's own operationalActions.detectionEngineer
// fields (report-derived); the last three are deterministic, no-LLM
// categories derived from Malware/Threat Actor Intelligence entities and
// CISA KEV entries respectively (see buildEntityDetectionBacklog/
// buildCveDetectionGaps).
export type DetectionBacklogCategory =
  | "newDetectionLogic"
  | "logSourcesRequired"
  | "detectionGaps"
  | "newAnalytics"
  | "mitreCoverageGaps"
  | "cveDetectionGaps";

export type DetectionBacklogStatus = "open" | "in_progress" | "implemented" | "wont_do";

export type DraftArtifactType =
  | "sigmaRule"
  | "sentinelKql"
  | "defenderXdrKql"
  | "splunkSpl"
  | "elasticEql"
  | "yaraRule"
  | "suricataRule"
  | "snortRule"
  | "defenderIocRecommendations"
  | "sentinelAnalyticRuleRecommendations"
  | "threatHuntingHypotheses"
  | "detectionEngineeringRecommendations";

export type DraftArtifactStatus = "Generated" | "Not Generated";
export type DraftArtifactConfidence = "High" | "Medium" | "Low";

/**
 * One of the 12 independently-assessed detection artifacts for a Detection
 * Backlog gap -- server/detectionRuleDraft.js. When status is "Generated",
 * content/confidence/humanReviewRequired/missingInformation/
 * implementationNotes are populated and reason/requiredInformation/
 * suggestedIntelligenceCollection are empty/null; when "Not Generated" it's
 * the reverse. Always a DRAFT for a human to review/adapt/test -- never a
 * validated or deploy-ready artifact.
 */
export interface DraftArtifact {
  type: DraftArtifactType;
  label: string;
  status: DraftArtifactStatus;
  content: string | null;
  confidence: DraftArtifactConfidence | null;
  humanReviewRequired: boolean | null;
  missingInformation: string[];
  implementationNotes: string | null;
  reason: string | null;
  requiredInformation: string[];
  suggestedIntelligenceCollection: string[];
}

export interface DraftArtifactRelatedRule {
  label: string;
  path: string;
  url: string;
}

/** The full 12-artifact draft response for one Detection Backlog gap -- see DraftArtifact above. */
export interface DraftArtifactSet {
  artifacts: DraftArtifact[];
  relatedRules: DraftArtifactRelatedRule[];
  model: string;
  generatedAt: string;
}

/** One detection-engineering gap: flattened out of an AI Summarization report's operationalActions.detectionEngineer, OR derived deterministically from a Malware/Threat Actor Intelligence entity (an active family with no matching public rule, or an actor's own ATT&CK technique), OR from a CISA KEV entry with no matching public rule (see server/detectionBacklog.js), paired with Detection Engineering's own tracked status/note -- this app's only source of truth for whether the gap's actually been closed -- and an optional AI-drafted artifact set (see DraftArtifactSet above). */
export interface DetectionBacklogItem {
  id: string;
  category: DetectionBacklogCategory;
  categoryLabel: string;
  description: string;
  status: DetectionBacklogStatus;
  note: string | null;
  statusUpdatedAt: string | null;
  draftArtifacts: DraftArtifactSet | null;
  source: "ai-report" | "entity";
  reportId: string;
  articleTitle: string;
  articleLink: string;
  articleSource: string;
  generatedAt: string;
  severity: Severity;
  cveIds: string[];
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

/** A named MITRE ATT&CK group recorded (real "uses" relationship) as using a given technique/tactic -- see server/correlate.js#actorsByTechniqueId. */
export interface AttackTacticHeatmapActor {
  name: string;
  url: string | null;
}

export interface AttackTacticHeatmapTechnique {
  id: string;
  name: string;
  url: string;
  count: number;
  actors: AttackTacticHeatmapActor[]; // capped -- see actorCount for the true total
  actorCount: number;
}

export interface AttackTacticHeatmapCell {
  tactic: string;
  total: number;
  intensity: number; // 0-1, relative to the hottest tactic
  techniques: AttackTacticHeatmapTechnique[];
  actors: AttackTacticHeatmapActor[]; // deduped across every technique observed under this tactic, capped
}

export interface DetectionRuleRef {
  label: "YARA-Rules" | "SigmaHQ";
  path: string;
  url: string;
}

export interface TrendingMalwareEntry {
  family: string;
  count: number;
  sources: string[];
  techniques: AttackTechnique[];
  detectionRules: DetectionRuleRef[];
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
  // "ransomware"/"otx-tagged" are source-provenance tags (ransomware.live,
  // OTX pulse adversary tags); the ThreatActorType values are real actor-type
  // classifications for actors sourced purely from news-derived intelligence
  // (server/threatActorIntelligence.js) that aren't already ransomware/OTX
  // tracked -- see server/correlate.js#mergeThreatActors.
  type: "ransomware" | "otx-tagged" | ThreatActorType;
  campaignCount: number;
  lastActivity: string;
}

export interface GeoTargetingCountry {
  countryCode: string; // ISO 3166-1 alpha-2, e.g. "US"
  numericId: string; // ISO 3166-1 numeric, matches the world-atlas topojson id
  count: number;
  topActors: Array<{ name: string; count: number }>;
}

/** Full (unsliced) country list -- see server/correlate.js#computeGeoTargeting. */
export interface GeoTargeting {
  countries: GeoTargetingCountry[];
  sampleSize: number;
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

export interface IocLookupResult {
  source: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  [key: string]: unknown;
}

// --- Platform-wide intelligence assessment framework -- see
// server/investigation/{evidence,cveExploitState,verdictEngine,actionability}.js.
// One shared evidence -> verdict -> confidence/severity -> actionability
// pipeline used by every entity type (IOC, CVE, actor, malware, campaign,
// ransomware group, ASN, country, artifact), instead of each type computing
// its own ad hoc, inconsistent judgment. The platform's own collected
// evidence is the source of truth; the AI layer only narrates over it (see
// GraphInsights/CorrelationSummary/AiInvestigationReport below), never
// invents it.

/** Direct/Corroborating/Attribution carry real weight toward a verdict; Indirect/Contextual never do alone (e.g. ASN/hosting-provider ownership is always Contextual); Negative is an explicit clean/benign signal; Conflicting marks evidence that disagrees with other evidence for the same indicator. */
export type EvidenceCategory = "direct" | "corroborating" | "indirect" | "contextual" | "negative" | "conflicting" | "attribution";
export type EvidencePolarity = "malicious" | "suspicious" | "benign" | "neutral";

/** One cited, source-attributed fact -- never a bare number. `rawField` records exactly which raw field this was derived from, for audit (e.g. "abuseConfidenceScore"). */
export interface EvidenceItem {
  category: EvidenceCategory;
  source: string;
  claim: string;
  polarity: EvidencePolarity;
  weight: number; // 0-1, source-derived; never itself "the verdict"
  rawField: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
}

/** Strength-of-signal scale for an EvidenceCard, deliberately separate from `polarity` -- the UI derives its RED/AMBER/GREEN/BLUE/GRAY color from the two together (e.g. malicious+HIGH -> RED, benign -> GREEN regardless of level, contextual -> BLUE, "no finding" -> GRAY), not from level alone. */
export type EvidenceLevel = "HIGH" | "MEDIUM" | "LOW" | "CONTEXT" | "UNKNOWN";

/** One card per QUERIED source, always -- including an explicit "No finding" card (`level: "UNKNOWN"`, `finding: "No finding"`) for a source that returned a successful lookup but produced no classifiable item. This is what lets the UI show every source individually instead of compressing multiple sources into one sentence: a silent source must never be read as "clean" or merged into another source's finding. See server/investigation/evidence.js#buildEvidenceCards. */
export interface EvidenceCard {
  source: string;
  evidenceType: string;
  level: EvidenceLevel;
  polarity: EvidencePolarity;
  finding: string;
  reason: string;
  lastSeen: string | null;
}

/** Output of the Evidence Reconciliation stage -- see server/investigation/evidence.js#buildEvidence. `independentSourceCount` counts distinct source FAMILIES (this platform's own cross-referenced data counts as one, regardless of how many entities it matched), not raw item count. `cards` is the per-source roster the UI renders directly; `items` stays the category-grouped view verdictEngine.js reads. */
export interface EvidenceReconciliation {
  items: EvidenceItem[];
  cards: EvidenceCard[];
  hasConflict: boolean;
  conflictDescription: string | null;
  sourceCount: number;
  independentSourceCount: number;
}

/** The one verdict-state enum every entity type resolves to -- see server/investigation/verdictEngine.js. "Conflicting Intelligence" always wins over any individual item's strength; "Insufficient Evidence" is distinct from "Clean-Benign" (the former means nothing was checked/found, the latter means checks came back explicitly clean). */
export type VerdictState =
  | "Confirmed Malicious"
  | "Malicious"
  | "Suspicious"
  | "Conflicting Intelligence"
  | "Unconfirmed"
  | "Clean-Benign"
  | "Informational"
  | "Insufficient Evidence";

/** Confidence = how sure we are, derived only from evidence quantity/independence/agreement/recency -- never from how bad the finding is. */
export interface VerdictConfidenceFactors {
  sourceCount: number;
  independentSourceCount: number;
  corroborationCount: number;
  recencyDays: number | null;
  reasoning: string;
}

/** Severity = how bad it would be if true, derived from entity-type-specific impact factors -- never from how sure we are. `businessContext` is honestly "Not Applicable" until this platform has real asset/business-context integration. */
export interface VerdictSeverityFactors {
  potentialImpact: string;
  scope: string;
  technicalSeverity: string;
  businessContext: string;
  reasoning: string;
}

/** The full output of the Confidence + Severity/Priority stages -- see server/investigation/verdictEngine.js#computeVerdict. Confidence and severity are computed independently (separate factor lists above) then combined with the evidence pattern into one `state`. */
/** Whether to block this indicator at the perimeter/EDR -- derived from `analystDecision` below, never independently computed, so the two can't disagree. Only ever "Block" when the verdict state itself reflects corroborated malicious evidence AND (for network/file IOCs on shared/cloud/VPN infrastructure) an actual malware/actor/campaign attribution, not reputation alone. "Not Applicable" for entity types blocking doesn't apply to (CVEs, actors, campaigns, artifacts, etc.). */
export type BlockRecommendation = "Block" | "Monitor — Do Not Block" | "Do Not Block" | "Not Applicable";

/**
 * The richer, type-agnostic analyst action -- computed in code from verdict
 * state plus two moderating signals also read from the evidence itself
 * (never re-derived by an AI layer): whether the indicator sits on known
 * shared/cloud/VPN/datacenter infrastructure (see
 * server/investigation/verdictEngine.js#hasSharedInfrastructureSignal), and
 * whether there's an actual malware/actor/campaign attribution (not bare
 * reputation). Strong external reputation alone, on shared infrastructure,
 * with no attribution, caps at "Investigate If Observed Internally" rather
 * than "Block" -- a confirmed attribution (e.g. a matched malware family)
 * overrides that caution even on shared hosting.
 */
export type AnalystDecision = "Block" | "Investigate Immediately" | "Investigate If Observed Internally" | "Monitor" | "Watchlist" | "Do Not Block" | "No Action Required";

export interface VerdictResult {
  state: VerdictState;
  label: string;
  confidence: "High" | "Medium" | "Low";
  confidenceFactors: VerdictConfidenceFactors;
  severity: Severity;
  severityFactors: VerdictSeverityFactors;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  recommendedPriority: "Immediate" | "High" | "Normal" | "Low";
  analystDecision: AnalystDecision;
  analystDecisionReasoning: string;
  blockRecommendation: BlockRecommendation;
  blockRecommendationReasoning: string;
  reasoning: string;
  evidence: EvidenceReconciliation;
  /** Human-readable descriptions of every detected disagreement between sources -- empty unless evidence.hasConflict. */
  conflicts: string[];
}

/**
 * Six distinct CVE exploitation states -- see server/investigation/cveExploitState.js.
 * Deliberately keeps "confirmed exploited" (CISA KEV, an observed fact),
 * "exploitation reported" (news language, unconfirmed), "exploit code
 * available" (Exploit-DB/GitHub, capability without confirmed use), and
 * "predicted high risk" (EPSS, a probability, not an observation) as four
 * separate concepts that must never collapse into one another.
 */
export type CveExploitationState =
  | "confirmed_actively_exploited"
  | "exploitation_reported_unconfirmed"
  | "public_exploit_available"
  | "poc_only"
  | "predicted_high_risk_epss"
  | "no_known_exploitation";

export interface CveExploitationAssessment {
  state: CveExploitationState;
  label: string;
  reasoning: string;
  kev: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
  exploitsAvailable: number;
  verifiedExploitsAvailable: number;
  githubPocsAvailable: number;
  newsReportsExploitationLanguage: Array<{ title: string; link: string; source: string }>;
}

/** How strong a relationship-graph edge's claim actually is, independent of which code path produced it -- see RELATIONSHIP_SEMANTICS in server/investigation/investigationGraph.js. `impliesColocationOnly` guards against e.g. "shares ASN with" ever being read as attribution. */
export type RelationshipClaimStrength =
  | "explicit-record"
  | "attribution"
  | "infrastructure-colocation"
  | "cross-reference"
  | "reverse-lookup"
  | "algorithmic-guess"
  | "unresolved-mention";

export interface RelationshipSemantics {
  claimStrength: RelationshipClaimStrength;
  impliesAttribution: boolean;
  impliesColocationOnly: boolean;
  guardrailNote: string | null;
}

export interface GraphEdgeConflict {
  relationship: string;
  why: string;
  source: string;
}

/**
 * A user-facing 5-value confidence scale for entity-search relationships --
 * always DERIVED from a GraphEdge's existing `semantics.claimStrength` +
 * `confidence`, never stored or computed independently. See
 * server/investigation/relationshipConfidenceLabel.js#labelFor(). An
 * `infrastructure-colocation` edge (e.g. "shares ASN with") is always
 * CONTEXTUAL regardless of confidence score -- the concrete enforcement of
 * "shared infrastructure is never attribution."
 */
export type RelationshipConfidenceLabel = "DIRECT" | "STRONG" | "MODERATE" | "WEAK" | "CONTEXTUAL";

/** One concrete, entity-type-specific recommended action -- never generic "investigate the IOC" text. See server/investigation/actionability.js#buildActionabilityGuidance. */
export interface ActionabilityAction {
  action: string;
  rationale: string;
  role: "socAnalyst" | "threatHunter" | "detectionEngineer" | "incidentResponse" | "threatIntel" | "vulnerabilityManagement";
  priority: "Immediate" | "High" | "Normal" | "Low";
}

export interface ActionabilityGuidance {
  entityType: IndicatorType;
  actions: ActionabilityAction[];
  huntingQueries: Array<{ platform: string; query: string; source: string; sourceUrl: string }>;
  /** Roles this entity type genuinely has nothing actionable for -- an honest omission, not a silent gap. */
  notApplicable: string[];
}

// --- Intelligence Investigation Console -- see server/investigation/index.js ---
// The full 16-type detection surface (replaces the old 4-type ip/domain/
// url/hash-only IOC Search), auto-classified server-side, never picked by
// the user.
export type IndicatorType =
  | "cve"
  | "ip"
  | "domain"
  | "url"
  | "sha256"
  | "sha1"
  | "md5"
  | "email"
  | "fileName"
  | "processName"
  | "registryKey"
  | "userAgent"
  | "ransomwareGroup" // matched against a real ransomware.live/RansomWatch/RansomLook group name -- see server/investigation/detect.js
  | "country" // matched against server/data/country-names.json
  | "asn"
  | "name" // malware family / threat actor / campaign / organization / victim -- resolved against this app's own entity stores (see server/investigation/index.js#resolveGraphTarget's victim fallback)
  | "unknown";

/** The one shared set of fields every indicator type renders, regardless of what kind it is -- `verdict` is the single output of the shared Evidence -> Confidence -> Severity pipeline (see server/investigation/verdictEngine.js), never invented independently per type. */
export interface UniversalOverview {
  indicator: string;
  indicatorType: IndicatorType;
  verdict: VerdictResult;
  /** Non-null only for `type === "cve"` -- the CVE-specific exploitation-state assessment feeding `verdict`, see server/investigation/cveExploitState.js. */
  cveExploitationState: CveExploitationAssessment | null;
  firstSeen: string | null;
  lastSeen: string | null;
  activeCampaigns: string[];
  associatedThreatActors: string[];
  mitreAttackMapping: Array<{ id: string; name: string; tactic: string | null }>;
  /** Populated only after "Generate AI Report" runs -- null until then, see AiInvestigationReport.businessImpact. */
  businessImpact: string | null;
  aiInvestigationSummary: string | null;
}

/** Cross-reference hits against this app's own already-ingested intelligence -- see server/investigation/crossReference.js. Powers the Related Intelligence section for every indicator type. */
export interface InvestigationRelatedIntelligence {
  matchedMalwareFamilies: string[];
  associatedThreatActors: string[];
  activeCampaigns: string[];
  matchingAiReports: Array<{ id: string; articleTitle: string; articleLink: string; articleSource: string; publishedDate: string }>;
  relatedIocs: Array<{ indicator: string; indicatorType: string; malwareFamily: string; firstSeen: string | null }>;
}

/**
 * The assembled "everything this platform knows about this entity" result --
 * see server/investigation/entityCorrelation.js#buildEntityDossier(). Built
 * entirely from stores/functions that already exist (malware/actor/campaign
 * intelligence, ransomware/dark-web victim tracking, ATT&CK, CVE profiles,
 * AI Summarization reports, detection/hunting content) -- no new ingestion.
 * Every list here is real, deterministically-tallied data; the AI layer only
 * narrates over it (see shouldICare.js/correlationSummary.js), never invents
 * it. Attached to `moduleData.dossier` for `name`/`ransomwareGroup` searches.
 */
export interface EntityDossier {
  /** "ransomware-tracker-only" means this platform has victim disclosures for this name but no verified actor/malware/campaign profile -- never fabricated to look like a full profile. */
  sourceType: "verified-profile" | "ransomware-tracker-only" | "unverified-mention";
  primaryEntity: { type: "actor" | "malware" | "campaign"; name: string } | null;
  aliases: string[];
  malwareFamilyCount: number;
  campaignCount: number;
  cveCount: number;
  iocCount: number;
  victimCount: number;
  threatReportCount: number;
  campaigns: CampaignHistoryEntry[];
  associatedCves: AssociatedCveEntry[];
  iocInventory: IocInventoryBucket[];
  attackTechniques: Array<{ id: string; name: string; tactic: string | null; observedVia: string; source: string }>;
  victimsTargeting: VictimTargetingSummary;
  recentActivity: RecentActivity;
  threatReports: Array<{ id: string; articleTitle: string; articleLink: string; articleSource: string; publishedDate: string }>;
  detectionRules: Array<{ label: string; path: string; url: string }>;
  huntingQueries: Array<{ platform: string; query: string; description: string }>;
}

/**
 * "What has this entity actually done in the last `windowDays`" -- the fix
 * for entities whose all-time targetedIndustries/targetedCountries/
 * cveExploited (accumulated forever, never expiring) dilute toward "targets
 * everything" for a well-covered actor/campaign, silently burying a real,
 * recent, specific signal (a new industry, a new country, a new CVE, a
 * newly-observed victim) under years of history. See
 * server/threatActorIntelligence.js#recentSignal and
 * server/investigation/entityCorrelation.js#buildRecentActivity -- every
 * value here traces to a real, dated article or victim-disclosure record,
 * never inferred or invented. `hasRecentSignal: false` means genuinely no
 * activity in the window, not a data gap -- shown as an explicit, honest
 * "nothing recent" state rather than silently omitted.
 */
export interface RecentActivity {
  windowDays: number;
  hasRecentSignal: boolean;
  mostRecentDate: string | null;
  targetedIndustries: string[];
  targetedCountries: string[];
  cveExploited: string[];
  malwareUsed: string[];
  recentCampaigns: string[];
  recentVictims: Array<{ victim: string; sector: string | null; country: string | null; discoveredDate: string | null; source: string }>;
  sourceArticles: Array<{ title: string; link: string; source: string; publishedDate: string; via: string }>;
}

export interface CampaignHistoryEntry {
  name: string;
  bucket: "current" | "historical" | "undated";
  firstSeen: string | null;
  lastSeen: string | null;
  targetedIndustries: string[];
  targetedCountries: string[];
  associatedMalware: string[];
  cveIds: string[];
  initialAccessTechniques: Array<{ id: string; name: string }>;
  victimCount: number;
  iocCount: number;
  sources: string[];
}

export interface AssociatedCveEntry {
  cveId: string;
  relationship: "direct" | "inferred";
  /** e.g. "Direct: campaign.cveExploited (ATT&CK + news text match)" or "INFERRED -- via <actor>'s own CVE record, not a first-party malware↔CVE citation" -- always shown to the analyst, never hidden. */
  source: string;
  exploitationContext: string | null;
  affectedTech: string | null;
  campaignRelationship: string[];
  confidenceLabel: RelationshipConfidenceLabel;
}

export interface IocInventoryItem {
  indicator: string;
  firstSeen: string | null;
  lastSeen: string | null;
  /** Which matched malware family this indicator came from. */
  source: string;
}

export interface IocInventoryBucket {
  indicatorType: "ip" | "domain" | "url" | "hash" | "email";
  count: number;
  items: IocInventoryItem[];
}

export interface VictimTargetingSummary {
  totalVictims: number;
  byIndustry: Array<{ industry: string; count: number }>;
  byCountry: Array<{ country: string; count: number }>;
  sample: Array<{ victim: string; sector: string | null; country: string | null; discoveredDate: string | null; source: string }>;
}

/**
 * The full per-indicator investigation result -- moduleData's shape depends
 * on `type` (see server/investigation/{ip,domain,url,hash,cve,entity,artifact}Module.js
 * for exactly what each returns); left loosely typed here rather than as a
 * 16-way discriminated union since every consumer already narrows on `type`
 * before reading type-specific fields, same pattern this app already uses
 * for IocLookupResult's `[key: string]: unknown` source-specific payloads.
 */
export interface InvestigationResult {
  indicator: string;
  type: IndicatorType;
  overview: UniversalOverview;
  moduleData: Record<string, unknown>;
  relatedIntelligence: InvestigationRelatedIntelligence | null;
  notConfigured: string[];
  rateLimited: string[];
  skipped: { source: string; reason: string }[];
  /** This search's seed Investigation Graph node, computed server-side in the same pass -- see server/investigation/index.js#computeGraphResult. Null only when no graph node type could be resolved at all. */
  graph: GraphNodeResult | null;
  /** Set only for a `name`-type search that resolved through a known alias (e.g. searched "Cozy Bear", this platform tracks it as "APT29") -- see server/investigation/knownAliasGroups.js. Null for every other search. */
  resolvedCanonicalName: string | null;
  /** Every intelligence layer this search actually consulted, and whether each found anything -- see server/investigation/coverage.js. `nothingFound` should only ever be true once every layer below genuinely came up empty. */
  coverage: SearchCoverage;
  /** The graph's own edges (plus any cross-referenced AI report not already an edge), flattened and ranked by confidence/recency -- see server/investigation/rankResults.js. */
  rankedFindings: RankedFinding[];
  /** Concrete, entity-type-specific next steps derived from this search's verdict/evidence -- see server/investigation/actionability.js. */
  actionability: ActionabilityGuidance;
}

export interface RankedFinding {
  label: string;
  entityType: GraphNodeType | "report";
  relationship: string;
  confidenceScore: number;
  reasoning: string;
  lastSeen: string | null;
  sources: string[];
}

export interface SearchCoverageLayer {
  name: string;
  checked: boolean;
  hitCount: number;
  summary: string;
}

export interface SearchCoverage {
  layers: SearchCoverageLayer[];
  nothingFound: boolean;
}

// --- Investigation Graph -- see server/investigation/investigationGraph.js ---
// Analyst-grade node-and-edge graph: start from any entity type, expand any
// node to discover its real relationships, click any newly-added node to
// expand further (infinite pivoting). Every edge is backed by a real field
// this app already computes; a relationship type with no supporting data
// anywhere in this app is listed in `unavailableRelationships` with a
// plain-language reason instead of a silently-empty section. `asn` is a
// leaf-only type (see backend file header) -- expanding one always returns
// zero edges, it exists only so an ASN can render as a normal node when
// pivoted to from an IP.
export type GraphNodeType =
  | "actor" | "campaign" | "malware" | "cve" | "victim" | "ip" | "domain" | "url" | "hash"
  | "email" | "fileName" | "processName" | "registryKey" | "userAgent" | "attackTechnique" | "country" | "report" | "asn" | "industry";

export type GraphConfidence = "High" | "Medium" | "Low";

export interface GraphEdge {
  targetType: GraphNodeType;
  targetKey: string;
  targetLabel: string;
  relationship: string;
  /** Technical provenance label (e.g. "Direct: actor.malwareUsed") -- kept for the tooltip; `reasoning` is the analyst-facing text. */
  why: string;
  /** Analyst-readable sentence explaining why this relationship exists, including real supporting-report counts/sources when known -- see buildReasoning() in server/investigation/investigationGraph.js. */
  reasoning: string;
  confidence: GraphConfidence;
  /** 0-100, the numeric score classifyConfidence()'s tier badge is derived from -- see scoreConfidence() in server/investigation/investigationGraph.js. */
  confidenceScore: number;
  firstSeen: string | null;
  lastSeen: string | null;
  /** Null when not meaningfully computable for this relationship type -- render as "not tracked", never as 0 (which would imply zero evidence). */
  supportingReportCount: number | null;
  sources: string[];
  /** Claim-strength classification for this edge's relationship type -- see RELATIONSHIP_SEMANTICS in server/investigation/investigationGraph.js. Guards against e.g. an infrastructure-colocation edge ("shares ASN with") ever being read as attribution. */
  semantics: RelationshipSemantics;
  /** Other relationship claims this platform found about the same target that disagree with this edge -- see dedupeEdges(). Empty when no conflict was detected; conflicting duplicates are preserved here instead of being silently dropped. */
  conflictsWith: GraphEdgeConflict[];
}

export interface GraphNode {
  type: GraphNodeType;
  id: string;
  label: string;
  summary: string | null;
  found: boolean;
  metadata: Record<string, unknown> | null;
}

export interface GraphNodeResult {
  node: GraphNode;
  edges: GraphEdge[];
  unavailableRelationships: Array<{ relationshipType: string; reason: string }>;
  /** Present only when this result came from investigationGraph.js#getExpandedGraph (entity-type searches -- name/ransomwareGroup) -- one extra GraphNodeResult per auto-expanded hop-1 node (capped, top-confidence targets only), each tagged with the seed edge's own targetType/targetKey so the frontend can merge it using the SAME key its placeholder node was already created under. Absent/empty for every IOC-type search, which stays single-hop. */
  additionalNodes?: Array<GraphNodeResult & { seedType: GraphNodeType; seedKey: string }>;
}

/**
 * AI Investigation Summary -- see server/investigation/graphInsights.js.
 * Synthesizes an Investigation Graph node's relationships instead of
 * restating them. Unlike AiInvestigationReport below, this one is fired
 * automatically once relationships finish loading (see
 * src/hooks/useInvestigationWorkspace.ts), not on a manual button click.
 */
export interface GraphInsights {
  summary: string;
  standoutRelationships: string[];
  likelyAttackChain: string | null;
  strongestActorMatch: { name: string; reasoning: string } | null;
  priorityInvestigationTargets: Array<{ entity: string; entityType: string; reasoning: string }>;
  crossReportPatterns: string[];
  recommendations: string[];
  model: string;
  provider: string;
  generatedAt: string;
}

/**
 * AI Correlation Summary -- see server/investigation/correlationSummary.js.
 * Reasons across a search's FULL unified result (graph edges, cross-
 * referenced entities, ranked findings, real industry data), not just one
 * graph node's direct edges the way GraphInsights above does. The narrative
 * fields (whatIsThis/whyItMatters/relationshipNarrative/
 * infrastructureReuseAssessment/nextSteps) are model-authored; every list
 * field below that is real, deterministically-tallied data passed straight
 * through, never model-authored.
 */
export interface CorrelationSummary {
  whatIsThis: string;
  whyItMatters: string;
  relationshipNarrative: string;
  infrastructureReuseAssessment: string;
  nextSteps: string[];
  industriesAffected: Array<{ industry: string; relevance: string; reportTitle: string }>;
  reusedInfrastructure: Array<{ indicator: string; indicatorType: string; malwareFamily: string | null }>;
  attackTechniques: Array<{ id: string; name: string }>;
  victimsTargeted: string[];
  relatedActors: string[];
  relatedCampaigns: string[];
  relatedMalware: string[];
  model: string;
  provider: string;
  generatedAt: string;
}

/**
 * "Should I Care?" -- see server/investigation/shouldICare.js. The
 * human-centric synthesis layer that sits ABOVE the per-source Evidence
 * Cards (EvidenceReconciliation.cards) -- it never restates what each source
 * found (the cards already show that individually); it answers what the
 * combined picture means. Four explicit sections: Combined Intelligence
 * Assessment (combinedAssessment -- what the evidence indicates once
 * compared, including how conflicts/shared-infrastructure/independence were
 * weighed), Likely Malicious Intent (likelyMaliciousIntent -- only populated
 * when evidence genuinely supports a specific intent; otherwise an honest
 * "not established" statement, never inferred from reputation/ASN/naming
 * alone), Environmental Relevance (environmentalRelevance -- whether this
 * indicator is known to have touched this environment, honest
 * "cannot be determined" until this platform has real telemetry), and Next
 * Action (nextAction -- a concrete analyst step). `analystDecision` is
 * deterministic pass-through from the verdict engine, never model-authored;
 * the four prose fields are the model's narrative synthesis over the real
 * evidence/verdict data it was given, fail-closed validated against it (see
 * groundClaims.js) before being returned.
 */
export interface ShouldICareAssessment {
  analystDecision: AnalystDecision;
  combinedAssessment: string;
  likelyMaliciousIntent: string;
  environmentalRelevance: string;
  nextAction: string;
  model: string;
  provider: string;
  generatedAt: string;
}

/** On-demand only -- see AiInvestigationOperationalGuidance/AiInvestigationDetectionOpportunities below, and server/investigationAi.js. Never generated automatically on search. */
export interface AiInvestigationOperationalGuidance {
  socAnalyst: string;
  threatHunter: string;
  threatIntel: string;
  detectionEngineer: string;
  incidentResponse: string;
  vulnerabilityManagement: string;
}

export interface AiInvestigationDetectionOpportunities {
  sentinelKql: string[];
  sigma: string[];
  splunkSpl: string[];
  elastic: string[];
  yara: string[];
  detectionGaps: string[];
  huntingHypotheses: string[];
}

export interface AiInvestigationReport {
  whatThisIs: string;
  whyItMatters: string;
  likelyAttackerObjective: string;
  businessImpact: string;
  confidenceReasoning: string;
  recommendedInvestigationPath: string[];
  immediateContainmentRecommendations: string[];
  operationalGuidance: AiInvestigationOperationalGuidance;
  detectionOpportunities: AiInvestigationDetectionOpportunities;
  model: string;
  provider: string;
  generatedAt: string;
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
  topCves: Array<{ cveId: string; repoCount: number; newsMentionCount: number }>;
}

export interface SourceReliability {
  score: number | null; // 0-100, null until at least 2 days of history exist
  trackedDays: number;
}

export interface SourceHealth {
  key: string;
  label: string;
  online: boolean;
  lastSynchronized: number | null; // epoch ms
  error?: string;
  reliability: SourceReliability | null; // null for lookup-only sources, which have no real uptime signal
}

// -- AI Provider Health / Usage (server/ai/providerHealth.js, server/ai/aiRequestLog.js) --
export interface AiProviderHealth {
  label: string;
  model: string;
  configured: boolean;
  status: "healthy" | "cooldown" | "misconfigured" | "unconfigured";
  statusLabel: string;
  cooldownRemainingMs: number;
  successRate: number | null; // 0-100, null until at least 1 request recorded
  avgLatencyMs: number | null;
  totalSuccess: number;
  totalFailure: number;
  rateLimitCount: number;
  timeoutCount: number;
  authErrorCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastFailureReason: string | null;
}

export interface AiUsageByProvider {
  provider: string;
  requests: number;
  success: number;
  failure: number;
  totalTokens: number;
  avgLatencyMs: number | null;
}

export interface AiUsageByTask {
  task: string;
  requests: number;
  success: number;
  failure: number;
  totalTokens: number;
}

export interface AiUsageRollup {
  totalRequests: number;
  totalSuccess: number;
  totalFailure: number;
  totalTokens: number;
  cacheHits: number;
  byProvider: AiUsageByProvider[];
  byTask: AiUsageByTask[];
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

export interface CampaignsBreakdown {
  ransomware: number;
  attackCampaigns: number;
  otxPulses: number;
  /** Named campaigns identified purely from security-news-vendor coverage -- see server/campaignIntelligence.js. */
  newsVendors: number;
}

/** One rolling daily snapshot of the score -- see server/threatScoreHistory.js. */
export interface ThreatScoreSnapshot {
  date: string; // YYYY-MM-DD
  score: number;
  totalActiveCampaigns: number;
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
  /** Ransomware victim disclosures + MITRE ATT&CK named campaigns + OTX adversary-tagged pulses -- see campaignsBreakdown for the per-source split. */
  totalActiveCampaigns: number;
  campaignsBreakdown: CampaignsBreakdown;
  /** Oldest-first rolling daily history, one snapshot per calendar day (up to 30 days). */
  scoreHistory: ThreatScoreSnapshot[];
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
  exploits: CveProfileExploit[];
}

export type ThreatTimelineEventType = "kev" | "ransomware" | "malware" | "github" | "news";

export interface ThreatTimelineEvent {
  id: string;
  type: ThreatTimelineEventType;
  date: string; // ISO string
  title: string;
  detail: string | null;
  url: string | null;
  severity: "critical" | "high" | "medium" | "low";
  cveId: string | null;
  malwareFamily: string | null;
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

export interface ExploitEntry {
  exploitId: string;
  title: string;
  url: string;
  type: string;
  platform: string;
  datePublished: string | null;
  verified: boolean;
  cveIds: string[];
}

export interface ExploitIntelligence {
  totalCount: number;
  recentEntries: ExploitEntry[];
}

export interface CveProfileExploit {
  exploitId: string;
  title: string;
  url: string;
  verified: boolean;
  datePublished: string | null;
  platform: string;
}

export interface VulnCheckExploitReference {
  id: string;
  url: string;
  type: string;
}

export interface VulnCheckKevEntry {
  cveIds: string[];
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string | null;
  dueDate: string | null;
  requiredAction: string | null;
  ransomwareUse: boolean;
  exploitReferences: VulnCheckExploitReference[];
}

export interface VulnCheckKevCatalog {
  count: number;
  entries: VulnCheckKevEntry[];
  notConfigured?: boolean;
}

/** One article a malware family was mentioned in -- see server/malwareIntelligence.js. */
export interface MalwareIntelligenceArticleRef {
  title: string;
  link: string;
  source: string;
  publishedDate: string;
}

/**
 * One canonical, deduped malware-family record -- built by automatically
 * extracting names from news article text (server/malwareExtraction.js), no
 * manually maintained list. `verified` means confirmed against MITRE ATT&CK's
 * Software list or a live indicator feed; unverified records are reported by
 * news coverage alone and haven't been corroborated elsewhere yet.
 */
/** A live indicator (see IocRecord) matching this malware family, capped and attached directly to the entity -- see server/combinedExtractionJob.js#buildIocFamilyData. */
export interface MalwareIocRef {
  indicator: string;
  indicatorType: IocType;
  sources: string[];
  firstSeen: string;
}

export interface MalwareIntelligenceEntity {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  attackId: string | null;
  attackUrl: string | null;
  verified: boolean;
  iocSightings: number;
  iocs: MalwareIocRef[];
  /** Indicators extracted directly from a linked article's own text (vendor/researcher-published, not from the bulk ThreatFox/URLHaus/MalwareBazaar feeds) -- accumulated and deduped across every article mentioning this family, never reset by a bulk-feed reconcile pass. See server/malwareIntelligence.js#addArticleIocs. */
  articleIocs: MalwareIocRef[];
  firstSeen: string;
  lastSeen: string;
  mentionCount: number;
  articles: MalwareIntelligenceArticleRef[];
}

/**
 * One canonical, deduped malicious/dual-use tool record (remote access
 * software, C2 frameworks, red-team/pentest utilities reported as used by a
 * threat actor) -- built by automatically extracting names from news article
 * text (server/toolExtraction.js) and seeded/verified against MITRE ATT&CK's
 * Software list restricted to type "tool" only (never "malware", which stays
 * MalwareIntelligenceEntity's exclusively). See server/toolIntelligence.js.
 */
export interface ToolIntelligenceEntity {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  attackId: string | null;
  attackUrl: string | null;
  verified: boolean;
  usedByGroups: string[];
  firstSeen: string;
  lastSeen: string;
  mentionCount: number;
  articles: MalwareIntelligenceArticleRef[];
}

export type ThreatActorType = "APT" | "Cybercrime" | "Ransomware" | "Hacktivist" | "Initial Access Broker" | "Insider" | "Unknown";

export type ThreatActorIntelligenceArticleRef = MalwareIntelligenceArticleRef;

/**
 * One canonical, deduped threat-actor record -- built by automatically
 * extracting names from news article text (server/threatActorExtraction.js),
 * no manually maintained roster, seeded with every MITRE ATT&CK Groups entry.
 * `verified` means confirmed against ATT&CK's Groups list or a ransomware
 * tracker; unverified records are reported by news coverage alone.
 */
export interface ThreatActorIntelligenceEntity {
  id: string;
  name: string;
  aliases: string[];
  type: ThreatActorType;
  description: string | null;
  attackId: string | null;
  attackUrl: string | null;
  country: string | null;
  motivations: string[];
  activeSince: string | null;
  verified: boolean;
  malwareUsed: string[];
  targetedIndustries: string[];
  targetedCountries: string[];
  cveExploited: string[];
  techniqueIds: string[];
  firstSeen: string;
  lastSeen: string;
  mentionCount: number;
  articles: ThreatActorIntelligenceArticleRef[];
}

export type CampaignIntelligenceArticleRef = MalwareIntelligenceArticleRef;

/**
 * One canonical, deduped campaign/operation record -- built by automatically
 * extracting named campaigns from news article text (server/campaignExtraction.js),
 * no manually maintained list. `verified` means corroborated by at least two
 * independent sources or matched against a MITRE ATT&CK campaign's own
 * description text (ATT&CK's Campaigns list has no real display names to
 * match against directly, so this isn't the same kind of "confirmed by an
 * authoritative catalog" signal as malware/actors).
 */
export interface CampaignIntelligenceEntity {
  id: string;
  name: string;
  aliases: string[];
  description: string | null;
  attackId: string | null;
  attackUrl: string | null;
  verified: boolean;
  associatedActors: string[];
  associatedMalware: string[];
  targetedIndustries: string[];
  targetedCountries: string[];
  cveExploited: string[];
  firstSeen: string;
  lastSeen: string;
  mentionCount: number;
  articles: CampaignIntelligenceArticleRef[];
}

export type DarkWebFindingType = "Data Leak" | "Credential Dump" | "Initial Access Listing" | "Marketplace Listing" | "Forum Discussion" | "Extortion Threat" | "Other";

export type DarkWebIntelligenceArticleRef = MalwareIntelligenceArticleRef;

/**
 * One canonical, deduped dark-web-finding record -- built by automatically
 * extracting findings from OSINT vendor/researcher news coverage of
 * underground forums/marketplaces/Telegram channels (server/darkWebExtraction.js),
 * NOT from direct dark-web-forum scraping; every article behind a record
 * here is a public news/vendor RSS feed already tracked in
 * server/connectors/newsFeeds.js. `verified` means corroborated by at least
 * two independently-published sources -- there's no authoritative catalog of
 * dark-web activity to match against, so corroboration is the whole signal
 * (the same policy as CampaignIntelligenceEntity).
 */
export interface DarkWebIntelligenceEntity {
  id: string;
  name: string;
  aliases: string[];
  type: DarkWebFindingType;
  platform: string | null;
  victimOrg: string | null;
  verified: boolean;
  associatedActors: string[];
  associatedMalware: string[];
  targetedIndustries: string[];
  targetedCountries: string[];
  cveExploited: string[];
  firstSeen: string;
  lastSeen: string;
  mentionCount: number;
  articles: DarkWebIntelligenceArticleRef[];
}

/**
 * One user-curated name being continuously monitored across every
 * intelligence source this platform tracks -- see server/watchlist.js. A
 * name written as "Full Name (ABBR)" is split into `primary` + `aliases`
 * automatically so either form matches.
 */
export interface WatchlistKeyword {
  id: string;
  label: string;
  primary: string;
  aliases: string[];
  addedAt: string;
}

export type FlashReportSourceType = "news" | "malware" | "actor" | "campaign" | "darkweb" | "ransomware" | "github";

/** One watchlist match -- a tracked name found somewhere in the platform's data. See server/watchlistScanner.js. */
export interface FlashReport {
  id: string;
  keywordId: string;
  keywordLabel: string;
  sourceType: FlashReportSourceType;
  sourceLabel: string;
  title: string;
  url: string | null;
  snippet: string | null;
  foundAt: string;
  read: boolean;
  /** Whether the underlying mention was published within the last 48h at scan time -- see server/watchlist.js#RECENT_WINDOW_MS. Older backlog matches are recorded for reference but pre-marked read so they don't flood the unread banner. */
  recent: boolean;
}

/** Local RAG chatbot -- see server/rag/. Runs entirely against a local Ollama install, no paid API. */
export interface ChatHealth {
  ollamaAvailable: boolean;
  missingModels: string[];
  indexedChunks: number;
  chatModel: string;
  embedModel: string;
}

export type ChatRole = "user" | "assistant";

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

/** One piece of platform intelligence the answer was actually grounded in -- see server/rag/ragChat.js. */
export interface ChatSource {
  id: string;
  type: "cve" | "kev" | "ransomware" | "actor" | "technique" | "malware" | "campaign" | "darkweb" | "news";
  label: string;
  url: string | null;
  score: number;
}

export interface AiThreatSummaryCve {
  id: string;
  severity: Severity | "UNKNOWN";
  cvssScore: number | null;
  knownExploited: boolean;
  epssScore: number | null;
  sourceUrl: string;
}

/** Grounded (regex-extracted, never model-generated) IOCs -- see server/aiThreatSummary.js#extractIocs. mutexes/scheduledTasks/services are best-effort, quote-anchored extraction (high precision, deliberately low recall -- see server/githubIntel/extractor.js's pattern comments); user agents, certificates, process command lines, and cloud/OAuth resource names have no reliable extraction path from article prose at all and are never included here (that narrative lives in technicalAnalysis/operationalActions instead, clearly distinct as AI-synthesized rather than extracted). */
export interface AiThreatSummaryIocs {
  ipAddresses: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
  emailAddresses: string[];
  registryKeys: string[];
  /** Windows drive-letter and absolute Unix/Linux paths (e.g. "/var/tmp/license.tmp"), merged into one category. */
  filePaths: string[];
  fileNames: string[];
  ports: string[];
  eventIds: string[];
  namedPipes: string[];
  mutexes: string[];
  scheduledTasks: string[];
  services: string[];
  cweIds: string[];
  /** Literal command-line/PowerShell invocations quoted directly in the source article -- code spans or command-verb-anchored quotes only, never a paraphrase. */
  cliCommands: string[];
  userAgents: string[];
  /** Real MITRE ATT&CK technique IDs found literally in the article's own text (regex-matched against this app's synced catalog) -- a code-verified cross-check against the model's own synthesized `mitreAttack` mapping, not a replacement for it. */
  attackTechniqueIds: string[];
  /** Malware family names found literally in the article's own text (matched against this app's curated family list) -- a code-verified cross-check against the model's own synthesized `malware` array. */
  malwareNames: string[];
}

/** One shared provenance block for the entire iocs section (not per-indicator) -- every value in AiThreatSummaryIocs is extracted directly from the article's own text via regex, so source/confidence/vendorConfirmed/firstSeen are identical for every indicator in the report by construction. See server/aiThreatSummary.js#buildIocProvenance. */
export interface AiThreatSummaryIocProvenance {
  source: string;
  sourceUrl: string;
  confidence: "Confirmed";
  vendorConfirmed: true;
  firstSeen: string;
  extractionMethod: string;
}

export interface AiThreatSummaryMitreTechnique {
  technique: string;
  techniqueId: string | null;
  /** A quote/close paraphrase from the article supporting this technique -- entries with no evidence are dropped entirely during parsing, never reach the frontend as "Not Reported". */
  evidence: string;
  confidence: "High" | "Medium" | "Low";
  reason: string;
  killChainPhase: string;
}

export interface AiThreatSummaryReference {
  label: string;
  url: string;
}

/** Business-facing impact -- executive/leadership-consumable, no technical jargon. */
export interface AiThreatSummaryBusinessRisk {
  businessRisk: string;
  /** Leveled verdict for the risk framing above -- should agree with aiRiskScoring.priority; server-side validation flags (but doesn't silently resolve) a sharp disagreement between the two. */
  overallRiskLevel: "Critical" | "High" | "Medium" | "Low";
  operationalDisruption: string;
  likelihoodOfExploitation: string;
  impactIfUnpatched: string;
  industriesCommonlyTargeted: string[];
  regionsCommonlyTargeted: string[];
  requiresExecutiveAttention: boolean;
  /** The single most important 1-3 actions across every team, not a repeat of every recommendation elsewhere. */
  topActions: string[];
  /** What a reader would want that this article/data genuinely doesn't provide -- null if nothing notable is missing. */
  whatsMissing: string | null;
}

/**
 * A conditional decision aid, not a personalized verdict (this app has no
 * knowledge of the reader's own environment) -- "YES" for broadly-applicable/
 * mass-exploited risk, "NO" for narrow/theoretical risk most readers can
 * ignore, "UNKNOWN" (the common case for a specific-product vulnerability)
 * with reasoning that tells the reader exactly what to check in their own
 * stack.
 */
export interface AiThreatSummaryShouldICare {
  verdict: "YES" | "NO" | "UNKNOWN";
  reasoning: string;
}

/**
 * A self-service exposure check the reader runs against their own
 * environment (this app has no visibility into what's actually installed) --
 * `applicable` is false (all other fields "Not Applicable") for threat-actor/
 * malware-only or non-product news where there's nothing to check a version
 * against.
 */
export interface AiThreatSummaryExposureAssessment {
  applicable: boolean;
  product: string;
  howToCheckVersion: string;
  affectedVersions: string;
  affectedGuidance: string;
  notAffectedGuidance: string;
}

/**
 * Analyst-audience narrative (why this matters operationally / how attackers
 * may use it / enterprise impact / why defenders should care), distinct from
 * executiveSummary's business-audience framing -- 2-4 paragraphs, separated
 * by blank lines in the raw string.
 */
export type AiThreatSummaryIntelligenceAssessment = string;

/** Who/where/how this threat targets -- mitreTactics is derived from the grounded mitreAttack array, never model-authored (see server/aiThreatSummary.js#safeThreatRelevance). */
export interface AiThreatSummaryThreatRelevance {
  industriesAtRisk: string[];
  technologiesTargeted: string[];
  geographicFocus: string[];
  mitreTactics: string[];
}

export interface AiThreatSummaryOperationalImpactAssessment {
  businessImpact: string;
  detectionChallenges: string[];
  evasionTechniques: string[];
  attackerObjectives: string[];
}

/** Fixed 21-sector catalog -- see INDUSTRY_CATALOG in server/industryClassification.js (the single source of truth for this taxonomy, re-exported by server/aiThreatSummary.js for backward compatibility). Every report has all 21, most "Not Applicable"/"Low" by design; only genuinely-supported sectors are elevated. */
export type IndustryName =
  | "Financial Services"
  | "Insurance"
  | "Healthcare"
  | "Pharmaceuticals"
  | "Government"
  | "Manufacturing"
  | "Retail"
  | "Technology"
  | "Telecommunications"
  | "Media & Entertainment"
  | "Energy & Utilities"
  | "Education"
  | "Transportation & Logistics"
  | "Hospitality"
  | "Professional Services"
  | "Defense & Aerospace"
  | "Automotive"
  | "Real Estate"
  | "Construction"
  | "Agriculture"
  | "Cross-Industry / Enterprise";

export type IndustryRelevanceLevel = "Critical" | "High" | "Medium" | "Low" | "Not Applicable";

/** How an industryRelevance row's rating was actually grounded -- see server/industryClassification.js's INDUSTRY_TIER discipline, applied here to the AI Summarization report schema. EXPLICIT: the article itself names this sector/a victim in it. TECHNOLOGY: the rating rests only on this sector commonly running an affected product/vendor the article names, no explicit sector claim. NONE: relevance is "Not Applicable". Never treat TECHNOLOGY the same as EXPLICIT in UI copy -- "Technology-Relevant" is a materially weaker claim than "Targeted". */
export type IndustryRelevanceBasis = "EXPLICIT" | "TECHNOLOGY" | "NONE";

export interface AiThreatSummaryIndustryRelevance {
  industry: IndustryName;
  relevance: IndustryRelevanceLevel;
  confidence: "High" | "Medium" | "Low";
  whyAffected: string;
  potentialImpact: string[];
  likelyTargetAssets: string[];
  defensiveFocus: string[];
  riskScore: number;
  priority: "Immediate" | "High" | "Normal" | "Low";
  relevanceBasis: IndustryRelevanceBasis;
}

/**
 * Merges the former threatOverview/aiTechnicalSummary/affectedProducts/
 * vendorSeverityAssessment sections into one -- driven by an explicit
 * reasoning chain (what happened / why it matters / who's affected / is
 * exploitation confirmed) instead of a flat technical dump.
 */
export interface AiThreatSummaryTechnicalAnalysis {
  whatHappened: string;
  /** Technical/operational significance -- what an attacker gains, the blast radius -- distinct from the business-language executiveSummary. */
  whyItMatters: string;
  whoIsAffected: string;
  /** Confirmed active exploitation / public PoC only / theoretical, with the evidence. */
  exploitationStatus: string;
  attackVector: string[];
  rootCause: string[];
  exploitationDetails: string[];
  technicalFindings: string[];
  attackChain: string;
  initialAccess: string | null;
  privilegeEscalation: string | null;
  execution: string | null;
  persistence: string | null;
  defenseEvasion: string | null;
  lateralMovement: string | null;
  commandAndControl: string | null;
  dataTheft: string | null;
  ransomwareDeployment: string | null;
  products: string[];
  versions: string[];
  operatingSystems: string[];
  cloudServices: string[];
  applications: string[];
  vendorSeverity: string;
  activeExploitation: string;
  overallSocPriority: "Critical" | "High" | "Medium" | "Low";
}

export interface AiThreatSummaryActor {
  group: string;
  aliases: string[];
  motivation: string | null;
  targetSectors: string[];
  geography: string | null;
  knownCampaigns: string[];
}

export interface AiThreatSummaryMalware {
  family: string;
  capabilities: string[];
  persistence: string | null;
  payload: string | null;
  deliveryMechanism: string | null;
}

/** A real prior article about the same tracked campaign -- code-attached from CampaignIntelligenceEntity's own article history, never model-authored (see server/aiThreatSummary.js#buildCampaignContextBlock). */
export interface AiThreatSummaryPriorArticle {
  title: string;
  link: string;
  publishedDate: string;
  source?: string;
}

/**
 * "Hunters investigate campaigns, not one-off vulnerabilities" -- captures
 * what changed about a previously-tracked campaign, grounded ONLY in this
 * platform's own real prior coverage of it (priorArticles). `applicable` is
 * false (the common case) whenever no prior tracked instance of the same
 * campaign exists yet -- a first sighting has nothing to compare against, so
 * the honest answer is "not applicable," never an invented evolution
 * narrative.
 */
export interface AiThreatSummaryCampaignEvolution {
  applicable: boolean;
  previousActivity: string | null;
  whatChanged: string | null;
  why: string | null;
  likelyNextStep: string | null;
  priorArticles: AiThreatSummaryPriorArticle[];
}

/** One indicator from this report that's also linked to a different tracked malware family/actor/campaign, or appears in a different AI Summarization report -- see server/infrastructureReuse.js. */
export interface AiThreatSummaryReusedIndicator {
  indicator: string;
  indicatorType: string;
  linkedMalwareFamilies: string[];
  linkedThreatActors: string[];
  linkedCampaigns: string[];
  seenInOtherReports: AiThreatSummaryPriorArticle[];
}

/**
 * Computed live at serve time (GET /api/dashboard/ai-summaries[/:id]), never
 * persisted in the stored report JSON -- see server/infrastructureReuse.js.
 * Built entirely from real cross-referenced data (the same
 * crossReferenceIndicator() the Intelligence Investigation Console uses),
 * never AI-generated. No "victims" field: this platform has no per-victim
 * linkage for malware/actor IOCs, so rather than invent one, it's omitted.
 */
export interface AiThreatSummaryInfrastructureReuse {
  hasReuse: boolean;
  threatActors: string[];
  relatedMalwareFamilies: string[];
  relatedCampaigns: string[];
  matchedIndicators: AiThreatSummaryReusedIndicator[];
  timeline: Array<{ date: string; label: string; link: string | null }>;
}

export interface AiThreatSummaryConfidence {
  level: "High" | "Medium" | "Low";
  score: number | null;
  reasoning: string;
  /** Specific, concrete factors that increase confidence -- e.g. "Official CISA advisory", "KEV inclusion confirmed". */
  factorsPresent: string[];
  /** What would have increased confidence further but isn't available for this article. */
  factorsMissing: string[];
}

export interface AiThreatSummaryRiskScoring {
  score: number | null;
  priority: "Critical" | "High" | "Medium" | "Low";
  reasoning: string;
}

/** Platform-specific telemetry for an L1/L2 analyst -- real event IDs/tables, not "monitor logs." */
export interface AiThreatSummarySocAnalyst {
  telemetryToCheck: string[];
  whatToLookFor: string;
  immediateNextStep: string;
}

/** One row of the fixed 7-action checklist -- see RECOMMENDED_ACTION_CATALOG in server/aiThreatSummary.js. */
export interface AiThreatSummaryRecommendedAction {
  action: "Block Firewall" | "Block DNS" | "Add to Defender IOC" | "Create Sentinel Analytic Rule" | "Hunt in MDE" | "Search Proxy Logs" | "Search Email Gateway";
  applicable: boolean;
  details: string;
}

export interface AiThreatSummaryHuntHypothesis {
  hypothesis: string;
  dataSources: string[];
  /** The ordered, concrete procedure a hunter follows to test this hypothesis -- distinct from dataSources (what to query), this is the how-to. */
  investigationSteps: string[];
  positiveFindingLooksLike: string;
  falsePositiveNote: string;
}

/** Concrete, hunt-actionable behavioral signatures grouped by category -- empty categories mean this threat genuinely has no behavior there, not an omission. */
export interface AiThreatSummaryBehavioralIndicators {
  networkBehaviors: string[];
  processBehaviors: string[];
  authenticationAnomalies: string[];
  dnsActivity: string[];
  powershellActivity: string[];
  scheduledTasks: string[];
  registryModifications: string[];
  persistenceIndicators: string[];
}

export interface AiThreatSummaryThreatHunter {
  hypotheses: AiThreatSummaryHuntHypothesis[];
  behavioralIndicators: AiThreatSummaryBehavioralIndicators;
}

/** Existing-rule-aware detection engineering guidance -- checks Sigma/Elastic/Microsoft coverage before asking for new logic. */
export interface AiThreatSummaryDetectionEngineer {
  existingRulesAvailable: string[];
  recommendedAction: string;
  yaraApplicable: string | null;
  /** Named Microsoft Sentinel/Defender KQL query concepts specific to this threat -- [] if KQL isn't a fit. */
  kqlOpportunities: string[];
  /** Named Sigma rule concepts (logsource + detection logic) specific to this threat -- [] if not applicable. */
  sigmaOpportunities: string[];
  /** Named Splunk SPL search concepts specific to this threat -- [] if not applicable. */
  splOpportunities: string[];
  /** Any other detection logic that doesn't fit the three named platforms above (e.g. Elastic/EDR-native). */
  newDetectionLogic: string[];
  logSourcesRequired: string[];
  expectedFalsePositives: string;
  /** Blind spots -- what this attack could still evade even with the above detections in place. */
  detectionGaps: string[];
  /** How this threat would concretely show up in telemetry/logs/alerts in a typical enterprise environment. */
  likelyManifestation: string;
  /** Underlying attacker behaviors that are inherently detectable regardless of any specific rule -- distinct from newDetectionLogic's rule-building tasks. */
  behavioralDetectionOpportunities: string[];
}

/** Platform-specific guidance assuming Microsoft Defender XDR, Microsoft Sentinel, and Defender for Office 365 unless the article states otherwise. */
export interface AiThreatSummaryPlatformRecommendations {
  logSourcesToReview: string[];
  microsoftDefenderRecommendations: string[];
  microsoftSentinelRecommendations: string[];
  firewallDnsRecommendations: string[];
  emailSecurityRecommendations: string[];
  identityMonitoringRecommendations: string[];
  edrRecommendations: string[];
  /** Guidance for end users/employees, not security staff -- only populated when the attack vector genuinely involves user action (phishing, credential entry, social engineering). */
  userRecommendations: string[];
}

/** `applicable` is false (all other fields "Not Applicable"/[]) when the article involves no specific CVE. */
export interface AiThreatSummaryVulnerabilityManagement {
  applicable: boolean;
  affectedAssetsSummary: string;
  internetFacing: string;
  exploitMaturity: string;
  patchPriority: string;
  maintenanceWindowRecommendation: string;
  businessCriticality: string;
  compensatingControls: string[];
  knownWorkaround: string | null;
}

export interface AiThreatSummaryIncidentResponse {
  immediateTriageSteps: string[];
  containmentActions: string[];
  recoveryActions: string[];
}

/** Per-team action guidance -- replaces the former flat detection/hunting/IR/recommendation arrays and role-takeaway strings. */
export interface AiThreatSummaryOperationalActions {
  socAnalyst: AiThreatSummarySocAnalyst;
  recommendedActions: AiThreatSummaryRecommendedAction[];
  platformRecommendations: AiThreatSummaryPlatformRecommendations;
  threatHunter: AiThreatSummaryThreatHunter;
  detectionEngineer: AiThreatSummaryDetectionEngineer;
  vulnerabilityManagement: AiThreatSummaryVulnerabilityManagement;
  incidentResponse: AiThreatSummaryIncidentResponse;
  threatIntelTakeaway: string;
  executiveLeadershipTakeaway: string;
}

/** The four provenance labels this app assigns to report sections -- see server/aiThreatSummary.js#REPORT_SECTION_PROVENANCE for why this is a static, code-determined classification rather than the model self-reporting it. */
export type ReportSectionProvenanceLabel = "Vendor Confirmed Intelligence" | "AI Assessment" | "Analyst Recommendation" | "Future Outlook";

/** GET /api/dashboard/ai-summaries-provenance -- a flat map of report field name (dot-notation for nested operationalActions.* fields) to its provenance label. Static; fetch once and cache indefinitely. */
export type ReportSectionProvenanceMap = Record<string, ReportSectionProvenanceLabel>;

export type OperationalRecommendationTeam = "Threat Intelligence" | "Threat Hunting" | "Detection Engineering" | "SOC Operations" | "Vulnerability Management" | "Incident Response";

/** One row of the flat, prioritized cross-team checklist -- see server/aiThreatSummary.js's `safeOperationalRecommendations`. Distinct from AiThreatSummaryOperationalActions' deep per-team narrative sections: this is the scannable "what, in what order" view, not the "how exactly" detail. */
export interface OperationalRecommendation {
  team: OperationalRecommendationTeam;
  priority: "Critical" | "High" | "Medium" | "Low";
  recommendation: string;
  rationale: string;
}

/**
 * One enterprise-grade SOC threat intelligence report generated from a
 * single major vendor/CISA advisory article -- see server/aiThreatSummary.js.
 * Facts (severity, cves, iocs, mitreAttack, threatActors, malware) are
 * grounded in this app's own verified extraction/enrichment, never model
 * recall; businessRisk/technicalAnalysis/operationalActions are the local
 * LLM's own synthesis, driven by an explicit reasoning chain rather than a
 * flat "summarize this" ask. Currently generated only for Critical/High/
 * Medium severity articles -- Low is deliberately deferred, not dropped.
 */
export interface AiThreatSummaryReport {
  id: string;
  articleTitle: string;
  articleLink: string;
  articleSource: string;
  publishedDate: string;
  generatedAt: string;
  severity: Severity;
  cves: AiThreatSummaryCve[];
  iocs: AiThreatSummaryIocs;
  iocProvenance: AiThreatSummaryIocProvenance;
  references: AiThreatSummaryReference[];
  executiveHeadline: string;
  executiveSummary: string;
  intelligenceAssessment: AiThreatSummaryIntelligenceAssessment;
  businessRisk: AiThreatSummaryBusinessRisk;
  shouldICare: AiThreatSummaryShouldICare;
  exposureAssessment: AiThreatSummaryExposureAssessment;
  technicalAnalysis: AiThreatSummaryTechnicalAnalysis;
  threatRelevance: AiThreatSummaryThreatRelevance;
  operationalImpact: AiThreatSummaryOperationalImpactAssessment;
  industryRelevance: AiThreatSummaryIndustryRelevance[];
  mitreAttack: AiThreatSummaryMitreTechnique[];
  threatActors: AiThreatSummaryActor[];
  malware: AiThreatSummaryMalware[];
  /** The specific named campaign/operation this activity is part of, exactly as the article names it -- null for the common case of a standalone vulnerability/incident with no named operation. */
  campaignName: string | null;
  campaignEvolution: AiThreatSummaryCampaignEvolution;
  operationalActions: AiThreatSummaryOperationalActions;
  operationalRecommendations: OperationalRecommendation[];
  confidenceAssessment: AiThreatSummaryConfidence;
  aiRiskScoring: AiThreatSummaryRiskScoring;
  /** Present only on responses from GET /api/dashboard/ai-summaries[/:id] -- computed live, not part of the persisted report, see AiThreatSummaryInfrastructureReuse. */
  infrastructureReuse?: AiThreatSummaryInfrastructureReuse;
}

// --- Emerging Threats (Threat Priority Score ranking + aggregate industry
// heatmap across every AI Summarization report) -- see
// server/emergingThreatsRanking.js. Distinct from the unrelated
// "emergingThreats" connector (Proofpoint's compromised-IP blocklist). ---

export interface ThreatPriorityScoreFactor {
  value: number;
  weight: number;
  contribution: number;
}

export interface ThreatPriorityScore {
  score: number;
  factors: {
    /** aiRiskScoring.score when a report exists, otherwise a severity-tier proxy (critical/high/medium/low -> 100/70/40/15) -- see server/emergingThreatsRanking.js. */
    risk: ThreatPriorityScoreFactor;
    kev: ThreatPriorityScoreFactor;
    /** Bonus for a named actor/malware-attributed campaign -- the actor/malware counterpart to the kev bonus above. */
    namedThreat: ThreatPriorityScoreFactor;
    industryRisk: ThreatPriorityScoreFactor;
    recency: ThreatPriorityScoreFactor;
  };
}

export interface EmergingThreatEntry {
  id: string;
  articleTitle: string;
  articleSource: string;
  severity: Severity;
  publishedDate: string;
  /** null when no AI Summarization report exists yet for this article -- see EmergingThreatEntry.hasReport. */
  aiRiskPriority: "Critical" | "High" | "Medium" | "Low" | null;
  /** Cross-referenced directly against the live KEV catalog for every article, not just reported ones. */
  knownExploited: boolean;
  /** Whether a full AI Summarization report exists for this article -- most entries won't (see server/emergingThreatsRanking.js), which is expected, not a gap. */
  hasReport: boolean;
  topIndustry: { industry: IndustryName; relevance: IndustryRelevanceLevel } | null;
  threatPriorityScore: ThreatPriorityScore;
}

export interface AggregateIndustryHeatmapRow {
  industry: IndustryName;
  relevance: IndustryRelevanceLevel;
  confidence: "High" | "Medium" | "Low";
  riskScore: number;
  priority: "Immediate" | "High" | "Normal" | "Low";
  whyAffected: string;
  potentialImpact: string[];
  likelyTargetAssets: string[];
  defensiveFocus: string[];
  /** How many recent articles currently flag this sector Critical or High. */
  activeThreatCount: number;
  /** The article that drove this sector's current relevance/risk -- may or may not have a full AI Summarization report (see AggregateIndustryHeatmapRow.confidence: "Low" means keyword-derived, not AI-assessed). */
  topArticle: { id: string; title: string } | null;
  /** Every Critical/High article behind activeThreatCount, most-severe/most-recent first, capped at 20 -- lets a user verify the count instead of just trusting a number. activeThreatCount stays the true total even once this list is capped. */
  contributingArticles: { id: string; title: string; source: string; relevance: IndustryRelevanceLevel; publishedDate: string }[];
}

export interface EmergingThreatsRanking {
  entries: EmergingThreatEntry[];
  industryHeatmap: AggregateIndustryHeatmapRow[];
}

/** An article reference within an IndustryBriefing -- always a real article from the grounding pool, never model-authored (see server/industryBriefing.js). */
export interface IndustryBriefingArticleRef {
  id: string;
  title: string;
  source: string;
  publishedDate: string;
}

export interface IndustryBriefingThreat {
  name: string;
  whyEmerging: string;
  activityLevel: "Critical" | "High" | "Medium";
  /** Earliest publishedDate among this threat's own sourceArticles -- computed from real data, not model-authored. */
  firstObserved: string | null;
  /** True only if at least one of this threat's sourceArticles is cross-referenced against the live KEV catalog -- never a model claim. */
  activeExploitation: boolean;
  trend: "Increasing" | "Stable" | "Declining";
  sourceArticles: IndustryBriefingArticleRef[];
}

/** How this actor/malware/campaign was correlated to the industry -- see server/industryCorrelation.js. "direct": the entity's own real text/ransomware-victim data EXPLICITLY names this industry. "technology": the entity's own text doesn't name the industry, but mentions a product/vendor this sector commonly runs (server/industryClassification.js's TECHNOLOGY_RELEVANT/POTENTIALLY_EXPOSED signal) -- a real, current signal, just a weaker claim than explicit targeting. "cross-linked": linked to another directly-matched entity (shared malware/campaign). "historical": curated, widely-published sector affinity, only ever a real platform entity, used to fill remaining slots. */
export type IndustryCorrelationTier = "direct" | "technology" | "cross-linked" | "historical";

export interface IndustryBriefingActor {
  actor: string;
  /** Only set when this actor's national attribution is well-established and widely reported -- null if unattributed/uncertain, never guessed. */
  country: string | null;
  confidence: "High" | "Medium" | "Low";
  motivation: string;
  typicalTargets: string;
  recentCampaigns: string;
  ttps: string;
  sourceArticles: IndustryBriefingArticleRef[];
  /** Real threatActorIntelligence.js entity mentionCount/dates when this actor resolves to a known entity -- falls back to sourceArticles.length/null when it doesn't (see mergeActorNarrative in server/industryBriefing.js). */
  reportCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
  /** Deterministic correlation tier/score/reason from server/industryCorrelation.js -- independent of confidence above (the model's own High/Medium/Low judgment call on this specific narrative). */
  tier: IndustryCorrelationTier;
  confidenceScore: number;
  correlationReason: string;
}

export interface IndustryBriefingTechnique {
  technique: string;
  whyIncreasing: string;
  sourceArticles: IndustryBriefingArticleRef[];
}

/** A specific, ID-mapped MITRE ATT&CK technique -- distinct from IndustryBriefingTechnique above (broad category trends, no real ID required). techniqueId/techniqueName/tactic are validated against this app's own synced ATT&CK catalog, never trusted from the model. */
export interface IndustryBriefingAttackTechnique {
  techniqueId: string | null;
  techniqueName: string;
  tactic: string | null;
  whyUsed: string;
  exampleScenario: string;
  detectionPriority: "Critical" | "High" | "Medium";
  sourceArticles: IndustryBriefingArticleRef[];
}

/** Deterministically tallied from the briefing's own topAttackTechniques -- never separately asked of the model. */
export interface IndustryBriefingTacticSummary {
  tactic: string;
  techniqueCount: number;
}

export interface IndustryBriefingMalwareFamily {
  /** A real server/malwareIntelligence.js entity name -- always a platform-known family, from the deterministic tiered ranking in server/industryCorrelation.js, never invented (see mergeMalwareNarrative in server/industryBriefing.js). */
  name: string;
  type: string;
  primaryPurpose: string;
  initialInfectionMethod: string;
  persistenceMechanism: string;
  commonPayload: string;
  typicalVictims: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  trend: "Increasing" | "Stable" | "Declining";
  sourceArticles: IndustryBriefingArticleRef[];
  tier: IndustryCorrelationTier;
  confidenceScore: number;
  correlationReason: string;
}

/** Real campaignIntelligence.js entity or ransomware-group victim cluster, tiered/confidence-scored by server/industryCorrelation.js -- never model-authored (see rankCampaignsForIndustry in server/industryBriefing.js). */
export interface IndustryBriefingCampaign {
  name: string;
  associatedActors: string[];
  associatedMalware: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  verified: boolean;
  mentionCount: number;
  tier: IndustryCorrelationTier;
  confidenceScore: number;
  reason: string;
}

/** Real CVSS/EPSS/KEV data from the NVD/KEV/EPSS caches -- never model-authored (see criticalCvesForPool in server/industryBriefing.js). */
export interface IndustryBriefingCriticalCve {
  cveId: string;
  cvssScore: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  knownExploited: boolean;
  description: string | null;
}

export interface IndustryIocIndicator {
  indicator: string;
  indicatorType: string;
  malwareFamily: string | null;
  firstSeen: string | null;
}

/** Real IOCs pulled from this industry's own malware entities' iocs/articleIocs, plus email addresses from matched reports -- never model-authored (see buildIndustryIocFeed in server/industryBriefing.js). */
export interface IndustryIocFeed {
  indicators: IndustryIocIndicator[];
  totalCount: number;
}

/** A real stored AiThreatSummaryReport row matched into this industry's grounding pool -- fields come straight off the stored report, not re-authored (see recentReportsForPool in server/industryBriefing.js). */
export interface IndustryBriefingReport {
  id: string;
  articleTitle: string;
  articleLink: string;
  articleSource: string;
  publishedDate: string;
  severity: string;
  threatActors: string[];
  campaignName: string | null;
  executiveSummary: string | null;
}

export interface IndustryDetectionOpportunity {
  platform: string;
  query: string;
  source: string;
  sourceUrl: string;
  malware: string[];
  threatActors: string[];
}

/** Deterministic, per-platform detection queries reused from server/huntingLibrary.js#buildEntityHuntingQueries -- no new LLM call. */
export interface IndustryDetectionOpportunities {
  sentinelKql: IndustryDetectionOpportunity[];
  splunkSpl: IndustryDetectionOpportunity[];
  elastic: IndustryDetectionOpportunity[];
  sigma: IndustryDetectionOpportunity[];
  yara: IndustryDetectionOpportunity[];
}

export interface IndustryBriefing {
  industry: IndustryName;
  generatedAt: string;
  /** How many real articles fed this briefing -- see server/industryBriefing.js#poolForIndustry. */
  articleCount: number;
  dateRangeDays: number;
  executiveSummary: string;
  topEmergingThreats: IndustryBriefingThreat[];
  activeThreatActors: IndustryBriefingActor[];
  activeCampaigns: IndustryBriefingCampaign[];
  emergingAttackTechniques: IndustryBriefingTechnique[];
  topAttackTechniques: IndustryBriefingAttackTechnique[];
  tacticsSummary: IndustryBriefingTacticSummary[];
  malwareFamilies: IndustryBriefingMalwareFamily[];
  commonTargets: string[];
  vulnerabilityTrends: {
    /** Real CVE IDs cross-referenced against the live KEV catalog -- never model-authored. */
    kevEntries: { cveId: string; articleTitle: string; articleId: string }[];
    totalUniqueCves: number;
    commentary: string;
  };
  criticalCves: IndustryBriefingCriticalCve[];
  industryIocFeed: IndustryIocFeed;
  recentReports: IndustryBriefingReport[];
  detectionOpportunities: IndustryDetectionOpportunities;
  huntingOpportunities: IndustryDetectionOpportunity[];
  industryRiskAssessment: {
    currentThreatLevel: "Critical" | "High" | "Medium" | "Low";
    whyTargeted: string;
    mostLikelyAttackScenarios: string[];
    highestBusinessRisks: string[];
    technologiesRequiringAttention: string[];
  };
  recommendedDefensivePriorities: string[];
  threatIntelOutlook: string;
  /** Built directly from the real grounding article pool, never model-authored -- "citing CISA" only happens when the underlying article really is from a CISA feed. */
  references: IndustryBriefingArticleRef[];
}
