import { useEffect, useState } from "react";
import { AlertTriangle, Copy, Download, ExternalLink, Search, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "./ErrorState";
import { Section } from "./reportPrimitives";
import { NotConfiguredNotice, IpIntelligenceSection, DomainIntelligenceSection, UrlIntelligenceSection } from "./investigation/NetworkIndicatorSections";
import { HashIntelligenceSection } from "./investigation/HashSections";
import { CveIntelligenceSection } from "./investigation/CveSections";
import { EntityIntelligenceSection } from "./investigation/EntitySections";
import { ArtifactIntelligenceSection } from "./investigation/ArtifactSections";
import { AiSummaryPanel, DetectionOpportunitiesPanel, OperationalGuidancePanel } from "./investigation/AiReportSection";
import { RecommendedActionsPanel } from "./investigation/RecommendedActionsPanel";
import { RealDetectionsHuntingPanel } from "./investigation/RealDetectionsHuntingPanel";
import { ShouldICarePanel } from "./investigation/ShouldICarePanel";
import { SearchCoveragePanel } from "./investigation/SearchCoveragePanel";
import { EvidencePanel } from "./investigation/EvidencePanel";
import { WhatToInvestigateNextPanel } from "./investigation/WhatToInvestigateNextPanel";
import { RecommendationsPanel } from "./investigation/RecommendationsPanel";
import { SandboxAnalysisPanel } from "./investigation/SandboxAnalysisPanel";
import { InvestigationGraph } from "./InvestigationGraph";
import { useSelection } from "@/context/SelectionContext";
import { useGenerateInvestigationAiReport } from "@/hooks/useInvestigate";
import { useInvestigationWorkspace } from "@/hooks/useInvestigationWorkspace";
import { sectionFamilyFor, INDICATOR_TYPE_LABEL } from "@/investigation/moduleConfig";
import { virusTotalLookupUrl } from "@/lib/vtLookup";
import type { IndicatorType, InvestigationResult, MalwareIntelligenceEntity, CveRecord, CveProfile, DetectionRuleRef, VerdictState } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

interface WorkspaceProps {
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
  /** Search-prefill + auto-run destinations for the embedded Relationship Graph's "View Full Profile" actions -- see InvestigationGraph.tsx's NodeActions. Distinct from the deterministic re-search this page does on its own (see RelationshipCard's onFocus below), which stays on this one page instead of switching tabs. */
  goToCampaignSearch: (name: string) => void;
  goToMalwareSearch: (name: string) => void;
  goToAiSummarySearch: (title: string) => void;
  /** Seeds the search box and auto-runs it once -- used by other tabs' "pivot here" buttons so a click there lands on a fully-run investigation, not just a prefilled box. */
  initialQuery?: string | null;
}

// The 8-state VerdictState -> visual treatment. "Conflicting Intelligence"
// gets its own distinct color (cyan, not a severity color) since it isn't
// "how bad" -- it's "sources disagree, an analyst needs to look" -- and must
// never be visually folded into the critical/high/medium/low severity scale.
const VERDICT_STATE_COLOR: Record<VerdictState, "critical" | "high" | "medium" | "low" | "muted" | "cyan"> = {
  "Confirmed Malicious": "critical",
  Malicious: "high",
  Suspicious: "medium",
  "Conflicting Intelligence": "cyan",
  Unconfirmed: "muted",
  "Clean-Benign": "low",
  Informational: "muted",
  "Insufficient Evidence": "muted",
};
const COLOR_CLASSES: Record<"critical" | "high" | "medium" | "low" | "muted" | "cyan", { border: string; bg: string; text: string }> = {
  critical: { border: "border-critical/30", bg: "bg-critical/10", text: "text-critical" },
  high: { border: "border-high/30", bg: "bg-high/10", text: "text-high" },
  medium: { border: "border-medium/30", bg: "bg-medium/10", text: "text-medium" },
  low: { border: "border-low/30", bg: "bg-low/10", text: "text-low" },
  cyan: { border: "border-accent-cyan/30", bg: "bg-accent-cyan/10", text: "text-accent-cyan" },
  muted: { border: "border-white/10", bg: "bg-white/[0.03]", text: "text-muted" },
};

// Severity/Risk Level/Recommended Priority/Confidence render several
// different vocabularies (e.g. recommendedPriority's "Immediate"/"Normal"
// vs. severity's "CRITICAL"/"MEDIUM"), but all reduce to the same
// industry-standard critical/high/medium/low color scale -- matched by
// keyword rather than exact value so every vocabulary lands on the same
// colors instead of rendering as plain uncolored text.
function severityTextColor(value: string): string {
  const v = value.toLowerCase();
  if (v.includes("critical") || v.includes("immediate")) return COLOR_CLASSES.critical.text;
  if (v.includes("high")) return COLOR_CLASSES.high.text;
  if (v.includes("medium") || v.includes("normal")) return COLOR_CLASSES.medium.text;
  if (v.includes("low")) return COLOR_CLASSES.low.text;
  return "text-foreground";
}

function VerdictBanner({ overview }: { overview: InvestigationResult["overview"] }) {
  const { verdict } = overview;
  const color = VERDICT_STATE_COLOR[verdict.state];
  const classes = COLOR_CLASSES[color];
  const Icon = color === "critical" || color === "high" ? AlertTriangle : ShieldCheck;
  return (
    <div className={cn("flex items-start gap-3 rounded-xl border p-4", classes.border, classes.bg)}>
      <Icon className={cn("mt-0.5 h-5 w-5 shrink-0", classes.text)} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={color}>{verdict.state.toUpperCase()}</Badge>
          <span className="text-sm font-semibold text-foreground">{verdict.label}</span>
        </div>
        {verdict.conflicts.length > 0 && (
          <p className="mt-2 text-xs text-accent-cyan">
            Sources disagree on this indicator — see Intelligence Evidence below for each source's individual finding and Should I Care? for how the conflict is weighed.
          </p>
        )}
        <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
          <div>
            <span className="text-muted">Severity: </span>
            <span className={cn("font-semibold", severityTextColor(verdict.severity))}>{verdict.severity}</span>
          </div>
          <div>
            <span className="text-muted">Risk Level: </span>
            <span className={cn("font-semibold", severityTextColor(verdict.riskLevel))}>{verdict.riskLevel}</span>
          </div>
          <div>
            <span className="text-muted">Recommended Priority: </span>
            <span className={cn("font-semibold", severityTextColor(verdict.recommendedPriority))}>{verdict.recommendedPriority}</span>
          </div>
          <div>
            <span className="text-muted">Confidence: </span>
            <span className={cn("font-semibold", severityTextColor(verdict.confidence))}>{verdict.confidence}</span>
          </div>
          {verdict.blockRecommendation !== "Not Applicable" && (
            <div>
              <span className="text-muted">Block Recommendation: </span>
              <span className="font-semibold text-foreground" title={verdict.blockRecommendationReasoning}>
                {verdict.blockRecommendation}
              </span>
            </div>
          )}
          <div>
            <span className="text-muted">First Seen: </span>
            <span className="font-semibold text-foreground">{overview.firstSeen ? new Date(overview.firstSeen).toLocaleDateString() : "Not Reported"}</span>
          </div>
          <div>
            <span className="text-muted">Last Seen: </span>
            <span className="font-semibold text-foreground">{overview.lastSeen ? new Date(overview.lastSeen).toLocaleDateString() : "Not Reported"}</span>
          </div>
          <div>
            <span className="text-muted">Active Campaigns: </span>
            <span className="font-semibold text-foreground">{overview.activeCampaigns.length > 0 ? overview.activeCampaigns.join(", ") : "None Reported"}</span>
          </div>
          <div>
            <span className="text-muted">Associated Actor(s): </span>
            <span className="font-semibold text-foreground">{overview.associatedThreatActors.length > 0 ? overview.associatedThreatActors.join(", ") : "None Reported"}</span>
          </div>
        </div>
        {overview.cveExploitationState && (
          <p className="mt-2 text-xs">
            <span className="text-muted">Exploitation Status: </span>
            <span className="font-semibold text-foreground">{overview.cveExploitationState.label}</span>
          </p>
        )}
        {overview.mitreAttackMapping.length > 0 && (
          <p className="mt-2 text-xs text-muted">
            MITRE ATT&CK: <span className="font-mono text-foreground">{overview.mitreAttackMapping.map((t) => t.id).join(", ")}</span>
          </p>
        )}
      </div>
    </div>
  );
}

/** Just the AI Summarization report cross-references now -- matched malware/actor/campaign names moved to the richer Relationships section below (same data, but with why/confidence/dates/sources instead of a bare chip), so this isn't duplicated in two places. */
function RelatedAiReportsSection({ result }: { result: InvestigationResult }) {
  const rel = result.relatedIntelligence;
  if (!rel || rel.matchingAiReports.length === 0) return null;
  return (
    <Section title="AI Summaries &amp; Vendor Reports">
      <ul className="space-y-1 text-xs">
        {rel.matchingAiReports.map((r) => (
          <li key={r.id}>
            <a href={r.articleLink} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
              {r.articleTitle} <ExternalLink className="h-3 w-3" />
            </a>{" "}
            <span className="text-muted">— {r.articleSource}</span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

const IOC_CLASSIFICATION_LABEL: Record<string, string> = {
  malicious_observed: "Observed Malicious",
  infrastructure_context: "Infrastructure Context",
  benign_reference: "Benign Reference",
  unknown: "Unclassified",
};

/**
 * Full per-source citation trail for this exact indicator value, straight
 * from the canonical IOC store (server/iocIntelligence.js) -- the concrete
 * answer to "who reported this, in which article, on what date, saying
 * what exactly" that requirement #13 of the IOC pipeline overhaul asks for.
 * null canonicalRecord means this store has never independently observed
 * the value (distinct from "observed with zero sources," which can't
 * happen -- upsertIndicator always attaches at least one source).
 */
function SourceCitationsSection({ result }: { result: InvestigationResult }) {
  const record = result.relatedIntelligence?.canonicalRecord;
  if (!record || record.sources.length === 0) return null;
  const otherCount = record.sightingCount - 1;
  return (
    <Section title="Source Citations">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <Badge variant={record.classification === "malicious_observed" ? "critical" : record.classification === "unknown" ? "muted" : "cyan"}>
          {IOC_CLASSIFICATION_LABEL[record.classification] ?? record.classification}
        </Badge>
        <span className="text-muted">
          {record.confidence} confidence &middot; first seen {new Date(record.firstSeen).toLocaleDateString()} &middot; last seen {new Date(record.lastSeen).toLocaleDateString()}
        </span>
      </div>
      {otherCount > 0 && (
        <p className="mb-2 text-xs text-muted">
          {otherCount} other report{otherCount === 1 ? "" : "s"} also mention{otherCount === 1 ? "s" : ""} this indicator.
        </p>
      )}
      <ul className="space-y-2.5">
        {record.sources.map((s, i) => (
          <li key={`${s.articleLink ?? i}-${i}`} className="rounded-lg border border-white/10 bg-white/[0.02] p-2.5 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-1">
              {s.articleLink ? (
                <a href={s.articleLink} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-medium text-primary hover:underline">
                  {s.articleTitle ?? s.articleLink} <ExternalLink className="h-3 w-3" />
                </a>
              ) : (
                <span className="font-medium text-foreground">{s.articleTitle ?? "Unknown article"}</span>
              )}
              <span className="text-muted">{s.publishedDate ? new Date(s.publishedDate).toLocaleDateString() : ""}</span>
            </div>
            <p className="mt-1 text-muted">
              {s.articleSource ?? "Unknown source"} &middot; {s.extractionMethod === "regex-fulltext" ? "full-text extraction" : s.extractionMethod === "backfill-from-report" ? "AI Summarization report" : "title/summary extraction"}
            </p>
            {s.contextSnippet && <p className="mt-1 rounded bg-black/20 p-1.5 font-mono text-[11px] text-foreground/80">&hellip;{s.contextSnippet}&hellip;</p>}
          </li>
        ))}
      </ul>
    </Section>
  );
}

function QuickActions({ result }: { result: InvestigationResult }) {
  const [copied, setCopied] = useState(false);
  const vtType = result.type === "ip" ? "ip" : result.type === "domain" ? "domain" : result.type === "sha256" || result.type === "sha1" || result.type === "md5" ? "hash" : "url";
  const isIocType = result.type === "ip" || result.type === "domain" || result.type === "url" || result.type === "sha256" || result.type === "sha1" || result.type === "md5";

  function copyIndicator() {
    navigator.clipboard.writeText(result.indicator);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  function exportJson() {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `investigation-${result.indicator.replace(/[^a-z0-9.-]/gi, "_")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Section title="Quick Actions">
      <div className="flex flex-wrap gap-2 text-xs">
        <Button type="button" variant="outline" size="sm" onClick={copyIndicator}>
          <Copy className="h-3 w-3" /> {copied ? "Copied!" : "Copy Indicator"}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={exportJson}>
          <Download className="h-3 w-3" /> Export JSON
        </Button>
        {isIocType && (
          <a href={virusTotalLookupUrl({ indicator: result.indicator, indicatorType: vtType })} target="_blank" rel="noreferrer">
            <Button type="button" variant="outline" size="sm">
              VirusTotal <ExternalLink className="h-3 w-3" />
            </Button>
          </a>
        )}
        {(result.type === "sha256" || result.type === "sha1" || result.type === "md5") && (
          <a href={`https://www.hybrid-analysis.com/search?query=${encodeURIComponent(result.indicator)}`} target="_blank" rel="noreferrer">
            <Button type="button" variant="outline" size="sm">
              Hybrid Analysis <ExternalLink className="h-3 w-3" />
            </Button>
          </a>
        )}
        {result.type === "url" && (
          <a href={`https://urlscan.io/search/#page.url%3A%22${encodeURIComponent(result.indicator)}%22`} target="_blank" rel="noreferrer">
            <Button type="button" variant="outline" size="sm">
              URLScan.io <ExternalLink className="h-3 w-3" />
            </Button>
          </a>
        )}
        {result.type === "ip" && (
          <a href={`https://viz.greynoise.io/ip/${encodeURIComponent(result.indicator)}`} target="_blank" rel="noreferrer">
            <Button type="button" variant="outline" size="sm">
              GreyNoise <ExternalLink className="h-3 w-3" />
            </Button>
          </a>
        )}
      </div>
    </Section>
  );
}

/**
 * The Investigation Workspace -- the first screen for any investigation.
 * One search box, auto-detected type (all 16 indicator shapes plus
 * malware/actor/campaign names), and everything an analyst needs to decide
 * "what is this, why should I care, is it malicious, what's connected, what
 * should each team do next" without a second search anywhere else. Fuses
 * server/investigation/index.js#investigate() (verdict/why-care/related
 * intelligence) with server/investigation/investigationGraph.js (real
 * relationship edges + detection/hunting citations) via
 * useInvestigationWorkspace -- see that hook for exactly how.
 *
 * The full pan/zoom/multi-hop-expand Investigation Graph (formerly its own
 * "Investigation Graph" tab, later a collapsed footer toggle) is the
 * flagship, always-rendered relationship view on this page -- it auto-
 * selects the searched entity so its own side panel is the one and only
 * place this page shows that entity's edges (no separate "Relationships"
 * list duplicating it). Every other fact on this page follows the same
 * rule: it lives in exactly one place, and later sections reference it by
 * name rather than restating it.
 *
 * Page order: (1) Verdict (Conflicting Intelligence badge and conflict
 * pointer live here). (2) Intelligence Evidence (EvidencePanel.tsx's
 * per-source card grid, see server/investigation/evidence.js#buildEvidenceCards)
 * clubbed together with Search Coverage -- what every source found, and
 * what this platform even checked, side by side. (3) Should I Care?
 * (server/investigation/shouldICare.js's Overall Assessment / Combined
 * Intelligence Assessment / Likely Malicious Intent / Environmental
 * Relevance -- NOT Next Action, which now lives only in (6) below).
 * (4) Investigation Graph. (5) Investigation Summary -- the per-type
 * Indicator-Specific Intelligence detail under a plain heading; no AI
 * narrative lives here (the auto-generated graph-insights read was removed
 * as redundant with Should I Care above and Recommendations/the manual AI
 * Investigation Summary below). (6) What To Investigate Next -- merges
 * ShouldICarePanel's next-step guidance with the correlation engine's own
 * next-steps list into one place, since both were answering the same
 * question. (7) Recommendations -- the graph-insights engine's own
 * recommendations list, pulled out to its own section (still fetched
 * automatically even though its parent narrative is no longer displayed).
 * Then:
 * AI/vendor reports -> Recommended Actions (SOC/Detection
 * Engineering/Threat Intelligence/Incident Response) -> real Detections &
 * Hunting -> deeper opt-in AI Investigation Summary (the manual "Generate AI
 * Report" narrative) -> Quick Actions.
 */
export function InvestigationWorkspace({ onOpenActor, onOpenCampaign, goToCampaignSearch, goToMalwareSearch, goToAiSummarySearch, initialQuery }: WorkspaceProps) {
  const [input, setInput] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState<string | null>(null);
  const { selectCve, selectMalware } = useSelection();

  const workspace = useInvestigationWorkspace();
  const aiReportM = useGenerateInvestigationAiReport();
  const {
    investigateM,
    result,
    graphTarget,
    graphNode,
    recommendedActions,
    graphInsights,
    graphInsightsPending,
    correlationSummary,
    correlationSummaryPending,
    shouldICare,
    shouldICarePending,
    shouldICareError,
  } = workspace;

  useEffect(() => {
    if (initialQuery) runInvestigation(initialQuery);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery]);

  function runInvestigation(raw: string) {
    const query = raw.trim();
    if (!query) return;
    setInput(query);
    setSubmittedQuery(query);
    workspace.runInvestigation(query);
    aiReportM.reset();
  }

  function openMalware(entity: MalwareIntelligenceEntity, detectionRules: DetectionRuleRef[]) {
    selectMalware({ family: entity.name, count: entity.iocSightings, sources: entity.articles.map((a) => a.source), techniques: [], detectionRules });
  }

  const family = result ? sectionFamilyFor(result.type as IndicatorType) : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">Investigation Workspace</CardTitle>
        <p className="mt-1 text-xs text-muted">
          Paste anything from an alert — an IP, domain, URL, file hash, CVE ID, email, file/process name, registry key, user agent, ransomware group,
          country, ASN, or a malware/actor/campaign/organization name — and this platform correlates across every intelligence layer it has (live
          lookups, tracked entity stores, ransomware/dark-web disclosures, AI Summarization reports, the relationship graph) before concluding there's
          nothing to find. Aliases resolve automatically (e.g. "Cozy Bear" finds APT29). Type is auto-detected, no manual selection needed.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runInvestigation(input);
          }}
          className="flex flex-wrap gap-2"
        >
          <Input
            autoFocus
            placeholder="e.g. CVE-2026-31431, 185.220.101.5, evil-domain.com, a1b2c3…, LockBit, Cozy Bear, Germany, AS15169, phishing@evil.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="w-full font-mono text-sm sm:w-[28rem]"
          />
          <Button type="submit" disabled={investigateM.isPending || !input.trim()}>
            <Search className="h-3.5 w-3.5" />
            Investigate
          </Button>
        </form>

        {investigateM.isPending && (
          <div className="space-y-2">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}

        {!investigateM.isPending && investigateM.isError && <EmptyState message={(investigateM.error as Error).message} />}

        {!investigateM.isPending && result && submittedQuery && (
          <div className="space-y-5">
            <p className="text-xs text-muted">
              Detected as <span className="font-mono text-foreground">{INDICATOR_TYPE_LABEL[result.type as IndicatorType]}</span>: <span className="font-mono text-foreground">{result.indicator}</span>
              {result.resolvedCanonicalName && (
                <>
                  {" "}
                  — searched as <span className="font-mono text-foreground">{result.resolvedCanonicalName}</span>, this platform's tracked name for{" "}
                  <span className="font-mono text-foreground">{result.indicator}</span>
                </>
              )}
            </p>

            {/* 1. Conflicting Intelligence / verdict. */}
            <VerdictBanner overview={result.overview} />

            {/* 2. Intelligence Evidence -- Source by Source, clubbed with Search Coverage: what every source found, and what this platform even checked, together. */}
            <EvidencePanel evidence={result.overview.verdict.evidence} />

            <SearchCoveragePanel coverage={result.coverage} />

            {/* 3. Should I Care? (Overall Assessment / Combined Intelligence Assessment / Likely Malicious Intent / Environmental Relevance). */}
            <ShouldICarePanel assessment={shouldICare} pending={shouldICarePending} error={shouldICareError} overview={result.overview} />

            {/*
              4. Investigation Graph -- the primary relationship view on this
              page -- it already auto-selects the searched entity on load, so
              its side panel shows exactly the relationships a standalone
              "Relationships" section here would duplicate. One relationships
              view, not two. See the standing principle: each fact on this
              page lives in exactly one place; later sections reference it by
              name, never restate the value.
            */}
            {graphTarget && (
              <InvestigationGraph
                initialType={graphTarget.type}
                initialKey={graphTarget.key}
                seedResult={result.graph}
                goToTriageInvestigate={runInvestigation}
                goToCampaignSearch={goToCampaignSearch}
                goToMalwareSearch={goToMalwareSearch}
                goToActorSearch={onOpenActor}
                goToAiSummarySearch={goToAiSummarySearch}
                overview={result.overview}
              />
            )}

            {/* 5. Investigation Summary -- the per-type Indicator-Specific Intelligence detail, under one plain heading (no AI narrative here -- see Should I Care above and Recommendations/AI Investigation Summary below for the AI-generated reads). */}
            <Section title="Investigation Summary">
              {family === "network" && result.type === "ip" && (
                <IpIntelligenceSection data={result.moduleData as unknown as Parameters<typeof IpIntelligenceSection>[0]["data"]} onPivotToIndicator={runInvestigation} />
              )}
              {family === "network" && result.type === "domain" && <DomainIntelligenceSection data={result.moduleData as unknown as Parameters<typeof DomainIntelligenceSection>[0]["data"]} />}
              {family === "network" && result.type === "url" && <UrlIntelligenceSection data={result.moduleData as unknown as Parameters<typeof UrlIntelligenceSection>[0]["data"]} />}
              {family === "hash" && <HashIntelligenceSection data={result.moduleData as unknown as Parameters<typeof HashIntelligenceSection>[0]["data"]} />}
              {family === "cve" &&
                (result.moduleData.found ? (
                  <CveIntelligenceSection
                    cve={result.moduleData.cve as CveRecord}
                    profile={result.moduleData.profile as CveProfile | null}
                    onViewProfile={() => selectCve(result.moduleData.cve as CveRecord)}
                  />
                ) : (
                  <EmptyState message={`${result.indicator} not found in NVD or CIRCL.`} />
                ))}
              {family === "entity" && (
                <EntityIntelligenceSection
                  data={result.moduleData as unknown as Parameters<typeof EntityIntelligenceSection>[0]["data"]}
                  onOpenMalware={openMalware}
                  onOpenActor={onOpenActor}
                  onOpenCampaign={onOpenCampaign}
                  onPivotToIndicator={runInvestigation}
                />
              )}
              {family === "artifact" && <ArtifactIntelligenceSection note={result.moduleData.note as string} crossReference={result.relatedIntelligence!} />}
            </Section>

            {/* 6. What To Investigate Next -- merges ShouldICarePanel's next-step guidance with the correlation engine's own next-steps list (Section 1), plus the deterministic environmental-validation checklist (Section 2) -- this platform has no internal telemetry integration, so those two kinds of "next step" must never be conflated. */}
            <WhatToInvestigateNextPanel
              shouldICare={shouldICare}
              shouldICarePending={shouldICarePending}
              correlationSummary={correlationSummary}
              correlationSummaryPending={correlationSummaryPending}
              environmentalValidation={recommendedActions?.environmentalValidation ?? null}
              cveInvestigationSteps={recommendedActions?.cveInvestigationSteps ?? null}
              sandboxInvestigationSteps={recommendedActions?.sandboxInvestigationSteps ?? null}
            />

            {/* 7. Recommendations -- the AI Investigation Summary's own recommendations list. */}
            <RecommendationsPanel recommendations={graphInsights?.recommendations ?? null} pending={graphInsightsPending} model={graphInsights?.model} />

            {/* 8. Then the rest: AI/vendor reports, different-team Recommended Actions, real Detections & Hunting, the deeper opt-in AI Investigation Summary narrative, and Quick Actions. */}
            <RelatedAiReportsSection result={result} />
            <SourceCitationsSection result={result} />

            {recommendedActions && <RecommendedActionsPanel guidance={recommendedActions} />}

            <SandboxAnalysisPanel sandbox={result?.sandbox ?? null} />

            <RealDetectionsHuntingPanel graphNode={graphNode} />

            <AiSummaryPanel
              report={aiReportM.data}
              isPending={aiReportM.isPending}
              error={aiReportM.isError ? (aiReportM.error as Error).message : null}
              onGenerate={() => aiReportM.mutate(submittedQuery)}
            />
            <DetectionOpportunitiesPanel report={aiReportM.data} />
            <OperationalGuidancePanel report={aiReportM.data} />

            {Array.isArray(result.moduleData.lookupResults) && (
              <NotConfiguredNotice notConfigured={result.notConfigured} rateLimited={result.rateLimited} skipped={result.skipped} />
            )}

            <QuickActions result={result} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
