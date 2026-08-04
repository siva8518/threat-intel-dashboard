import { useEffect, useMemo, useState } from "react";
import { BrainCircuit, ChevronDown, ChevronRight, ExternalLink, ShieldAlert, Gauge, FileDown, FileType } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { SeverityBadge } from "./SeverityBadge";
import { DateRangeFilter, EMPTY_DATE_RANGE, isWithinDateRange, type DateRange } from "./DateRangeFilter";
import { Table, TableHead, TableBody, TableRow, TableHeaderCell, TableCell } from "@/components/ui/table";
import { useAiThreatSummaries, useAiSummaryProvenance } from "@/hooks/useAiThreatSummaries";
import type { AiThreatSummaryReport, Severity, AiThreatSummaryCampaignEvolution, AiThreatSummaryInfrastructureReuse } from "@/types/threat-intel";
import { cn } from "@/lib/utils";
import { downloadReportAsPdf, downloadReportAsWord } from "@/lib/reportExport";
import { buildOperationalGuidanceRows, EMPTY_OPERATIONAL_ACTIONS, EMPTY_PLATFORM_RECOMMENDATIONS } from "@/lib/operationalGuidance";
import { Section, FieldList, KeyValueBlock, GroupedLists } from "./reportPrimitives";

// Reports generated before the v2 schema (businessRisk/technicalAnalysis/
// operationalActions replacing the old flat section list) won't have these
// keys at all -- fall back to all-empty rather than crashing on
// report.businessRisk.businessRisk etc. Old reports simply render these
// sections as empty/hidden, same "reports are immutable once generated"
// pattern already used for every prior schema change in this feature.
const EMPTY_BUSINESS_RISK = {
  businessRisk: "Not Reported",
  operationalDisruption: "Not Reported",
  likelihoodOfExploitation: "Not Reported",
  impactIfUnpatched: "Not Reported",
  industriesCommonlyTargeted: [] as string[],
  regionsCommonlyTargeted: [] as string[],
  requiresExecutiveAttention: false,
  topActions: [] as string[],
  whatsMissing: null as string | null,
};

const EMPTY_TECHNICAL_ANALYSIS = {
  whatHappened: "Not Reported",
  whyItMatters: "Not Reported",
  whoIsAffected: "Not Reported",
  exploitationStatus: "Not Reported",
  attackVector: [] as string[],
  rootCause: [] as string[],
  exploitationDetails: [] as string[],
  technicalFindings: [] as string[],
  attackChain: "Not Reported",
  initialAccess: null as string | null,
  privilegeEscalation: null as string | null,
  execution: null as string | null,
  persistence: null as string | null,
  defenseEvasion: null as string | null,
  lateralMovement: null as string | null,
  commandAndControl: null as string | null,
  dataTheft: null as string | null,
  ransomwareDeployment: null as string | null,
  products: [] as string[],
  versions: [] as string[],
  operatingSystems: [] as string[],
  cloudServices: [] as string[],
  applications: [] as string[],
  vendorSeverity: "Not Reported",
  activeExploitation: "Not Reported",
  overallSocPriority: "Medium" as const,
};

const EMPTY_EXPOSURE_ASSESSMENT = {
  applicable: false,
  product: "Not Applicable",
  howToCheckVersion: "Not Applicable",
  affectedVersions: "Not Applicable",
  affectedGuidance: "Not Applicable",
  notAffectedGuidance: "Not Applicable",
};

const EMPTY_THREAT_RELEVANCE = {
  industriesAtRisk: [] as string[],
  technologiesTargeted: [] as string[],
  geographicFocus: [] as string[],
  mitreTactics: [] as string[],
};

const EMPTY_OPERATIONAL_IMPACT = {
  businessImpact: "Not Reported",
  detectionChallenges: [] as string[],
  evasionTechniques: [] as string[],
  attackerObjectives: [] as string[],
};

const EMPTY_CAMPAIGN_EVOLUTION: AiThreatSummaryCampaignEvolution = {
  applicable: false,
  previousActivity: null,
  whatChanged: null,
  why: null,
  likelyNextStep: null,
  priorArticles: [],
};

const EMPTY_INFRASTRUCTURE_REUSE: AiThreatSummaryInfrastructureReuse = {
  hasReuse: false,
  threatActors: [],
  relatedMalwareFamilies: [],
  relatedCampaigns: [],
  matchedIndicators: [],
  timeline: [],
};

/** "Hunters think in kill chains" -- surfaces which stages this report genuinely has no data for, distinct from the Kill Chain block above it (which shows what IS known). Built purely from fields the schema already marks null when unreported -- no new AI generation, no new backend field. */
function buildIntelligenceGaps(tech: AiThreatSummaryReport["technicalAnalysis"], malware: AiThreatSummaryReport["malware"]) {
  const namedMalware = malware.filter((m) => m.family !== "Not Reported");
  const gaps: string[] = [];
  if (!tech.initialAccess) gaps.push("Initial Access");
  if (!tech.persistence) gaps.push("Persistence");
  if (!tech.commandAndControl) gaps.push("Command & Control");
  if (!tech.lateralMovement) gaps.push("Lateral Movement");
  if (namedMalware.length === 0 || namedMalware.every((m) => !m.payload)) gaps.push("Payload");
  return gaps;
}

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / (60 * 60 * 1000));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function priorityVariant(priority: string): "critical" | "high" | "medium" | "low" | "muted" {
  if (priority === "Critical") return "critical";
  if (priority === "High") return "high";
  if (priority === "Medium") return "medium";
  if (priority === "Low") return "low";
  return "muted";
}

function ScoreGauge({ label, value, variant, title }: { label: string; value: string; variant: "critical" | "high" | "medium" | "low" | "muted"; title?: string }) {
  const iconClass = variant === "critical" ? "text-critical" : variant === "high" ? "text-high" : variant === "medium" ? "text-medium" : variant === "low" ? "text-low" : "text-muted";
  return (
    <div className="flex items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2" title={title}>
      <Gauge className={cn("h-4 w-4", iconClass)} />
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted">{label}</div>
        <div className="text-sm font-semibold text-foreground">{value}</div>
      </div>
    </div>
  );
}

// A one-time-per-report-view legend rather than a per-section badge --
// tagging all ~25 sections individually would need threading a provenance
// prop through every Section call site in this file for marginal added
// clarity over stating the rule once. The classification itself still comes
// from the backend's REPORT_SECTION_PROVENANCE (fetched via
// useAiSummaryProvenance, cached indefinitely -- see server/aiThreatSummary.js
// for why this is a static, code-determined map rather than the model
// self-reporting it), not restated here independently.
function ProvenanceLegend() {
  const { data } = useAiSummaryProvenance();
  if (!data) return null;
  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.02] px-3 py-2 text-[11px] text-muted">
      <span className="font-semibold text-foreground">How to read this report: </span>
      <Badge variant="low" className="mx-0.5">Vendor Confirmed</Badge>
      sections (CVEs, IOCs, severity, references) are extracted directly from the source, never generated.{" "}
      <Badge variant="cyan" className="mx-0.5">AI Assessment</Badge>
      sections (technical analysis, industry relevance, risk scoring) are the model's own synthesis, grounded in the article but not independently verifiable.{" "}
      <Badge variant="medium" className="mx-0.5">Analyst Recommendation</Badge>
      sections (detection engineering, hunting, IR guidance) are suggested actions, not confirmed facts.{" "}
      <Badge variant="muted" className="mx-0.5">Future Outlook</Badge>
      sections (threat intel/executive takeaways) are forward-looking trajectory judgment, not a prediction of certainty.
    </div>
  );
}

/** Stops the click from also toggling the parent row's expand/collapse -- these buttons sit inside that row's clickable header area. */
function DownloadButtons({ report }: { report: AiThreatSummaryReport }) {
  return (
    <div className="flex shrink-0 items-center gap-1" onClick={(e) => e.stopPropagation()}>
      <button
        type="button"
        onClick={() => downloadReportAsPdf(report)}
        title="Download as PDF"
        className="flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[11px] text-muted transition-colors hover:text-foreground"
      >
        <FileDown className="h-3 w-3" />
        PDF
      </button>
      <button
        type="button"
        onClick={() => downloadReportAsWord(report)}
        title="Download as Word (.doc)"
        className="flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[11px] text-muted transition-colors hover:text-foreground"
      >
        <FileType className="h-3 w-3" />
        Word
      </button>
    </div>
  );
}

function IocRow({ label, values }: { label: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div>
      <div className="mb-1 text-xs font-semibold text-foreground">
        {label} <span className="font-normal text-muted">({values.length})</span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {values.map((v, i) => (
          <span key={i} className="rounded-md border border-white/[0.06] bg-black/20 px-2 py-0.5 font-mono text-xs text-foreground">
            {v}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Renders a short bulleted list inside a table cell -- "Not Available in Source" (not a blank cell) when a team genuinely has nothing here, per the review spec's explicit instruction not to fabricate guidance to fill a cell. */
function CellList({ items }: { items: string[] }) {
  if (items.length === 0) return <span className="text-muted">Not Available in Source</span>;
  return (
    <ul className="list-disc space-y-0.5 pl-3.5">
      {items.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </ul>
  );
}

function CellText({ text }: { text: string | null | undefined }) {
  if (!text || text === "Not Reported" || text === "Not Applicable") return <span className="text-muted">Not Available in Source</span>;
  return <>{text}</>;
}

/**
 * Single 8-column table replacing the former separate "Operational Actions"
 * priority table AND the five standalone per-team detailed-guidance blocks
 * below it -- one row per team (SOC Analyst, Threat Intelligence, Threat
 * Hunter, Detection Engineer, Vulnerability Management, Incident Response),
 * every column an analyst actually needs without paging through five
 * separate sections to assemble it.
 */
function OperationalGuidanceTable({ report }: { report: AiThreatSummaryReport }) {
  const rows = buildOperationalGuidanceRows(report);
  return (
    <Section title="Operational Guidance">
      <Table>
        <TableHead>
          <TableRow>
            <TableHeaderCell className="w-[9%]">Team</TableHeaderCell>
            <TableHeaderCell className="w-[7%]">Priority</TableHeaderCell>
            <TableHeaderCell className="w-[14%]">Recommended Action</TableHeaderCell>
            <TableHeaderCell className="w-[14%]">Detailed Guidance</TableHeaderCell>
            <TableHeaderCell className="w-[13%]">Telemetry / Log Sources</TableHeaderCell>
            <TableHeaderCell className="w-[14%]">Detection / Hunting Opportunities</TableHeaderCell>
            <TableHeaderCell className="w-[14%]">Immediate Next Steps</TableHeaderCell>
            <TableHeaderCell>Rationale</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={r.team}>
              <TableCell className="text-xs font-semibold text-foreground">{r.team}</TableCell>
              <TableCell>
                <Badge variant={priorityVariant(r.priority)}>{r.priority}</Badge>
              </TableCell>
              <TableCell className="text-xs text-foreground">
                <CellList items={r.actions} />
              </TableCell>
              <TableCell className="text-xs text-foreground">
                <CellList items={r.detailedGuidance} />
              </TableCell>
              <TableCell className="text-xs text-foreground">
                <CellList items={r.telemetry} />
              </TableCell>
              <TableCell className="text-xs text-foreground">
                <CellList items={r.detectionOpportunities} />
              </TableCell>
              <TableCell className="text-xs text-foreground">
                <CellText text={r.nextSteps} />
              </TableCell>
              <TableCell className="text-xs text-muted">
                <CellList items={r.rationale} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Section>
  );
}

type ExposureAnswer = "yes" | "no" | "unsure";

/**
 * A self-service exposure check the reader runs against their own
 * environment -- "Do you have {product}?" -> optional version note -> the
 * model's own affected-version description plus both branches of guidance.
 * Deliberately does NOT try to auto-determine whether a typed version is
 * "affected" (arbitrary vendor versioning schemes -- Exchange CUs, FortiOS
 * builds -- can't be reliably compared with a generic heuristic without
 * risking exactly the kind of fabricated confidence this report's grounding
 * rules exist to prevent); it guides the reader to the real answer instead
 * of pretending to compute it.
 */
function ExposureAssessment({ exposure }: { exposure: typeof EMPTY_EXPOSURE_ASSESSMENT }) {
  const [answer, setAnswer] = useState<ExposureAnswer | null>(null);
  if (!exposure.applicable) return null;

  return (
    <div className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2.5">
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Exposure Assessment</h4>
      <p className="text-sm text-foreground">
        Do you have <span className="font-semibold">{exposure.product}</span>?
      </p>
      <div className="mt-2 flex gap-1.5">
        {(["yes", "no", "unsure"] as const).map((opt) => (
          <button
            key={opt}
            type="button"
            onClick={() => setAnswer(opt)}
            className={cn(
              "rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
              answer === opt ? "border-primary bg-gradient-primary text-white" : "border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
            )}
          >
            {opt === "yes" ? "Yes" : opt === "no" ? "No" : "Not Sure"}
          </button>
        ))}
      </div>

      {answer === "no" && (
        <div className="mt-2.5 rounded-md border border-low/30 bg-low/5 px-2.5 py-2 text-xs">
          <span className="font-semibold text-low">Not applicable to you. </span>
          <span className="text-foreground">{exposure.notAffectedGuidance}</span>
        </div>
      )}

      {(answer === "yes" || answer === "unsure") && (
        <div className="mt-2.5 space-y-2 text-xs">
          <div>
            <span className="font-semibold text-foreground">How to check your version: </span>
            <span className="text-muted">{exposure.howToCheckVersion}</span>
          </div>
          <div>
            <span className="font-semibold text-foreground">Affected versions (per this article): </span>
            <span className="text-muted">{exposure.affectedVersions}</span>
          </div>
          {answer === "yes" && (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <div className="rounded-md border border-critical/30 bg-critical/5 px-2.5 py-2">
                <div className="font-semibold text-critical">If your version is listed above</div>
                <div className="mt-0.5 text-foreground">{exposure.affectedGuidance}</div>
              </div>
              <div className="rounded-md border border-low/30 bg-low/5 px-2.5 py-2">
                <div className="font-semibold text-low">If it isn't</div>
                <div className="mt-0.5 text-foreground">{exposure.notAffectedGuidance}</div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ReportRow({ report, expanded, onToggle }: { report: AiThreatSummaryReport; expanded: boolean; onToggle: () => void }) {
  const kevCount = report.cves.filter((c) => c.knownExploited).length;
  const totalIocs = Object.values(report.iocs).reduce((sum, list) => sum + (list?.length ?? 0), 0);
  // "Not Reported" is the model's explicit "the article names nothing here"
  // placeholder (see the "never invent facts" grounding in
  // server/aiThreatSummary.js), not a real actor/malware name -- confirmed
  // live it was rendering as its own card, indistinguishable from a genuine
  // one, whenever an article discussed a CVE/technique without naming an
  // actor or malware family. Same fix already applied to the Hunting Query
  // Library's aggregation (server/huntingLibrary.js).
  const namedThreatActors = report.threatActors.filter((a) => a.group !== "Not Reported");
  const namedMalware = report.malware.filter((m) => m.family !== "Not Reported");

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02]">
      <div className="flex w-full items-start justify-between gap-3 p-3">
        <button type="button" onClick={onToggle} className="flex min-w-0 flex-1 items-start gap-2 text-left">
          {expanded ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted" /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted" />}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-foreground">{report.articleTitle}</span>
              <SeverityBadge severity={report.severity} />
              <Badge variant={priorityVariant(report.aiRiskScoring.priority)} title={`AI-computed risk score: ${report.aiRiskScoring.score ?? "—"}/100. See "Risk Score" below for the reasoning.`}>
                {report.aiRiskScoring.priority} priority
              </Badge>
              {kevCount > 0 && (
                <Badge variant="critical" className="gap-1">
                  <ShieldAlert className="h-3 w-3" />
                  {kevCount} KEV
                </Badge>
              )}
              {/* Surfaces campaign identity at a glance in the collapsed row
                  too -- otherwise a reader has to expand a report to learn
                  it's part of a named operation at all. */}
              {report.campaignName && <Badge variant="cyan">{report.campaignName}</Badge>}
              {report.shouldICare && (
                <Badge
                  variant={report.shouldICare.verdict === "YES" ? "critical" : report.shouldICare.verdict === "NO" ? "low" : "medium"}
                  title={`Should I care? ${report.shouldICare.verdict} -- ${report.shouldICare.reasoning}`}
                >
                  Should I care? {report.shouldICare.verdict}
                </Badge>
              )}
            </div>
            <p className="mt-1 line-clamp-1 text-xs text-muted">{report.executiveSummary}</p>
          </div>
        </button>
        <div className="flex shrink-0 flex-col items-end gap-1.5 text-xs text-muted">
          <DownloadButtons report={report} />
          <span>{report.articleSource}</span>
          <span>{timeAgo(report.generatedAt)}</span>
        </div>
      </div>

      {expanded && (
        <div className="space-y-5 border-t border-white/[0.06] px-3 pb-4 pt-3 text-sm">
          {/* Comes first, always -- the reader needs to know how to read
              everything below before seeing any of it. */}
          <ProvenanceLegend />

          {/* 1. Executive Summary + Business Risk + Threat Relevance -- the
              "what happened, what's the business exposure, who's likely
              targeted" trio, grouped since they're all situational reads a
              leader or triage-first analyst wants in one pass. */}
          {(() => {
            const risk = report.businessRisk ?? EMPTY_BUSINESS_RISK;
            const relevance = report.threatRelevance ?? EMPTY_THREAT_RELEVANCE;
            return (
              <div>
                <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Executive Summary</h4>
                {report.executiveHeadline && <p className="mb-1.5 text-base font-semibold text-foreground">{report.executiveHeadline}</p>}
                <p className="text-foreground">{report.executiveSummary}</p>

                {risk.overallRiskLevel && (
                  <div className="mt-3">
                    <Badge variant={priorityVariant(risk.overallRiskLevel)}>Overall Risk: {risk.overallRiskLevel}</Badge>
                    {risk.requiresExecutiveAttention && (
                      <Badge variant="critical" className="ml-1.5">
                        Requires executive attention
                      </Badge>
                    )}
                  </div>
                )}
                <KeyValueBlock
                  title=""
                  pairs={[
                    ["Business risk", risk.businessRisk],
                    ["Operational disruption", risk.operationalDisruption],
                    ["Likelihood of exploitation", risk.likelihoodOfExploitation],
                    ["Impact if unpatched", risk.impactIfUnpatched],
                  ]}
                />
                {/* Neither threatRelevance.industriesAtRisk nor
                    businessRisk.industriesCommonlyTargeted are shown here --
                    both just restate the Affected Industries section further
                    down, which already covers which sectors this threat
                    targets (with relevance level, not just a bare list). */}
                <GroupedLists
                  title=""
                  groups={[
                    ["Regions impacted", risk.regionsCommonlyTargeted ?? []],
                    ["Technologies targeted", relevance.technologiesTargeted],
                    ["Geographic focus", relevance.geographicFocus],
                    ["MITRE tactics", relevance.mitreTactics],
                  ]}
                />
              </div>
            );
          })()}

          {/* 1b. What Happened & Why It Matters -- pulled up front and given
              its own prominent callout rather than left buried inside the
              dense Technical Analysis section further down (removed from
              that section's KeyValueBlock below to avoid showing the same
              two answers twice). "Why It Matters" is deliberately
              technicalAnalysis.whyItMatters, not intelligenceAssessment --
              the former is worded to answer exactly this question
              (including, per its own prompt instruction, explicit
              campaign-level significance when the article describes a named
              operation rather than a standalone vulnerability);
              intelligenceAssessment is a distinct, deeper trajectory
              judgment and keeps its own spot in Threat Assessment below. */}
          {(() => {
            const tech = report.technicalAnalysis ?? EMPTY_TECHNICAL_ANALYSIS;
            if (tech.whatHappened === "Not Reported" && tech.whyItMatters === "Not Reported") return null;
            return (
              <div className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <h5 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">What Happened?</h5>
                    <p className="text-sm text-foreground">{tech.whatHappened}</p>
                  </div>
                  <div>
                    <h5 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">
                      {report.campaignName ? `Why Does "${report.campaignName}" Matter?` : "Why Does This Matter?"}
                    </h5>
                    <p className="text-sm text-foreground">{tech.whyItMatters}</p>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* 1c. Campaign Evolution -- "hunters investigate campaigns, not
              one-off IOCs." Only renders when this platform has real prior
              coverage of the same named campaign to compare against
              (campaignEvolution.applicable); a first-ever sighting has
              nothing to compare to, so it's correctly absent rather than
              showing an invented "no prior activity" placeholder. */}
          {(() => {
            const evolution = report.campaignEvolution ?? EMPTY_CAMPAIGN_EVOLUTION;
            if (!evolution.applicable) return null;
            return (
              <Section title={`Campaign Evolution${report.campaignName ? `: ${report.campaignName}` : ""}`}>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <KeyValueBlock title="Previous Campaign" pairs={[["Previously known", evolution.previousActivity]]} />
                  <KeyValueBlock title="New Campaign" pairs={[["What's changed", evolution.whatChanged]]} />
                </div>
                <KeyValueBlock
                  title=""
                  pairs={[
                    ["Why", evolution.why],
                    ["Likely next step", evolution.likelyNextStep],
                  ]}
                />
                {evolution.priorArticles.length > 0 && (
                  <div className="mt-2">
                    <h5 className="mb-1 text-xs font-semibold text-foreground">Prior Coverage</h5>
                    <ul className="space-y-1">
                      {evolution.priorArticles.map((a, i) => (
                        <li key={i}>
                          <a href={a.link} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                            {a.title} <ExternalLink className="h-3 w-3" />
                          </a>
                          <span className="ml-1 text-xs text-muted">
                            ({a.source ? `${a.source}, ` : ""}
                            {new Date(a.publishedDate).toLocaleDateString()})
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </Section>
            );
          })()}

          {/* 2. Threat Assessment -- every scoring/judgment signal in one
              place: the two headline gauges, the analyst's own written
              opinion, and the full factor-by-factor reasoning behind both
              scores (previously a separate "Confidence & Risk Reasoning"
              section near the bottom -- consolidated here since it's the
              same "how sure are we, and why" question as the gauges above
              it). */}
          <div>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Threat Assessment</h4>
            <div className="flex flex-wrap gap-2">
              <ScoreGauge
                label="Risk Score"
                value={report.aiRiskScoring.score == null ? "—" : `${report.aiRiskScoring.score}/100`}
                variant={priorityVariant(report.aiRiskScoring.priority)}
                title={`Why ${report.aiRiskScoring.score ?? "—"}/100: ${report.aiRiskScoring.reasoning}`}
              />
              <ScoreGauge
                label="Analysis Confidence"
                value={report.confidenceAssessment.score != null ? `${report.confidenceAssessment.level} (${report.confidenceAssessment.score}%)` : report.confidenceAssessment.level}
                variant={report.confidenceAssessment.level === "High" ? "low" : report.confidenceAssessment.level === "Medium" ? "medium" : "high"}
                title={`Why ${report.confidenceAssessment.level}: ${report.confidenceAssessment.reasoning}`}
              />
            </div>
            {/* Confirmed live this reads as a contradiction otherwise -- "Confidence" sits right next to a risk/priority score, so a reader assumes it's on the same severity scale. It isn't: it's the model's own certainty that *this report* accurately reflects the source article, completely independent of how severe the underlying threat is. "Medium priority, High confidence" means "I'm quite sure this really is Medium," not "actually High." */}
            <p className="mt-1.5 text-[11px] text-muted">Analysis Confidence is the model's certainty that this report reflects the source article -- not a severity signal.</p>

            {report.intelligenceAssessment && report.intelligenceAssessment !== "Not Reported" && (
              <div className="mt-3 space-y-2 text-foreground">
                {report.intelligenceAssessment.split(/\n{2,}/).map((paragraph, i) => (
                  <p key={i}>{paragraph}</p>
                ))}
              </div>
            )}

            {/* Evidence supporting the confidence score above, in place of a
                free-text "reasoning" paragraph -- concrete, checkable facts
                (Official Vendor Advisory, CISA KEV, Active Exploitation
                Confirmed, NVD Reference, ...) read as more trustworthy than
                a restated sentence, and this is exactly what
                confidenceAssessment.factorsPresent already is. */}
            {(report.confidenceAssessment.factorsPresent?.length > 0 || report.confidenceAssessment.factorsMissing?.length > 0) && (
              <div className="mt-3">
                <h5 className="mb-1 text-xs font-semibold text-foreground">Evidence Supporting Confidence</h5>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {report.confidenceAssessment.factorsPresent?.length > 0 && (
                    <ul className="space-y-0.5 text-xs text-muted">
                      {report.confidenceAssessment.factorsPresent.map((f, i) => (
                        <li key={i} className="text-low">
                          ✓ {f}
                        </li>
                      ))}
                    </ul>
                  )}
                  {report.confidenceAssessment.factorsMissing?.length > 0 && (
                    <ul className="space-y-0.5 text-xs text-muted">
                      {report.confidenceAssessment.factorsMissing.map((f, i) => (
                        <li key={i}>– {f}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* 3. Should I Care + Exposure Assessment + affected technologies/
              products/versions -- the self-service "does this apply to me,
              and specifically what should I check" bundle. */}
          {(() => {
            const tech = report.technicalAnalysis ?? EMPTY_TECHNICAL_ANALYSIS;
            return (
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Should I Care &amp; Exposure</h4>
                {report.shouldICare && (
                  <div className="mb-3 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
                    <p className="text-foreground">
                      <span className="font-semibold">{report.shouldICare.verdict}.</span> {report.shouldICare.reasoning}
                    </p>
                  </div>
                )}
                <ExposureAssessment exposure={report.exposureAssessment ?? EMPTY_EXPOSURE_ASSESSMENT} />
                <GroupedLists
                  title="Affected Technologies & Products"
                  groups={[
                    ["Products", tech.products],
                    ["Versions", tech.versions],
                    ["Operating systems", tech.operatingSystems],
                    ["Cloud services", tech.cloudServices],
                    ["Applications", tech.applications],
                  ]}
                />
              </div>
            );
          })()}

          {/* 4. Affected Industries -- a single concise list of only the
              sectors the article genuinely supports flagging (relevance !==
              "Not Applicable"), not the full 10-row scored heatmap. This
              per-report view intentionally doesn't infer or pad -- an
              article naming no sector shows the explicit fallback line
              rather than a table implying every industry was assessed. The
              full scored heatmap (all 10 sectors, risk scores, defensive
              guidance) still exists in the Emerging Threats tab's aggregate
              view (IndustryHeatmap), which is a genuinely different use case
              (cross-report trend, not a single article's read). */}
          {(() => {
            const flagged = (report.industryRelevance ?? []).filter((r) => r.relevance !== "Not Applicable");
            return (
              <Section title="Affected Industries">
                {flagged.length === 0 ? (
                  <p className="text-sm text-muted">Affected Industries: Not specifically identified by the vendor.</p>
                ) : (
                  <ul className="space-y-1">
                    {flagged.map((r) => (
                      <li key={r.industry} className="flex items-center gap-2 text-sm">
                        <Badge variant={priorityVariant(r.relevance)}>{r.relevance}</Badge>
                        <span className="font-medium text-foreground">{r.industry}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>
            );
          })()}

          {/* 5. Technical Analysis, Attack Details, Kill Chain & MITRE
              ATT&CK Mapping -- one heading, since these all answer the same
              underlying "how does this attack actually work" question at
              increasing levels of structure (narrative -> categorized
              bullets -> ordered kill-chain stages -> catalog-validated
              technique IDs). Named threat actors/malware are folded in here
              too, right after the technique mapping, since they're the
              "who/what" half of the same technical picture. */}
          {(() => {
            const tech = report.technicalAnalysis ?? EMPTY_TECHNICAL_ANALYSIS;
            return (
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Technical Analysis, Attack Details, Kill Chain &amp; MITRE ATT&amp;CK Mapping</h4>
                {/* whatHappened/whyItMatters are shown once already, in the
                    prominent "What Happened & Why It Matters" callout near
                    the top of the report -- not repeated here. */}
                <KeyValueBlock
                  title="Technical Analysis"
                  pairs={[
                    ["Who is affected", tech.whoIsAffected],
                    ["Active exploitation", tech.activeExploitation],
                  ]}
                />
                {tech.exploitationStatus && tech.exploitationStatus !== "Not Reported" && (
                  <p className="mt-1.5 text-sm">
                    <span className="font-semibold text-foreground">Exploitation status: </span>
                    <span className="text-foreground">{tech.exploitationStatus}</span>
                    {report.references[0] && (
                      <>
                        {" "}
                        <a href={report.references[0].url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                          (see source)
                        </a>
                      </>
                    )}
                  </p>
                )}
                {tech.vendorSeverity && tech.vendorSeverity !== "Not Reported" && (
                  <p className="mt-1.5 text-sm">
                    <span className="font-semibold text-foreground">Vendor severity: </span>
                    <span className="text-foreground">{tech.vendorSeverity}</span>
                    {/* This is the vendor's own stated rating, quoted directly from
                        the article -- it can legitimately differ from this report's
                        overall severity badge at the top, which also weighs KEV
                        status, CVSS, and confirmed active exploitation, not just the
                        vendor's own label. Not a contradiction to resolve; a distinct
                        signal worth showing separately. */}
                    <span className="ml-1 text-xs text-muted">
                      (the vendor's own rating -- this report's overall severity above also factors in KEV/CVSS/active exploitation, so it can differ)
                    </span>
                  </p>
                )}
                <GroupedLists
                  title="Attack Details"
                  groups={[
                    ["Attack vector", tech.attackVector],
                    ["Root cause", tech.rootCause],
                    ["Exploitation details", tech.exploitationDetails],
                    ["Technical findings", tech.technicalFindings],
                  ]}
                />
                {/* Why this attack is hard to detect/evade -- relocated here
                    from the former standalone "Operational Impact" section
                    (removed: its businessImpact field duplicated businessRisk
                    above, and detectionChallenges/evasionTechniques/
                    attackerObjectives are technical attacker-behavior detail
                    that belongs alongside Attack Details, not a section of
                    their own). */}
                {(() => {
                  const impact = report.operationalImpact ?? EMPTY_OPERATIONAL_IMPACT;
                  return (
                    <GroupedLists
                      title="Detection Challenges & Evasion"
                      groups={[
                        ["Detection challenges", impact.detectionChallenges],
                        ["Evasion techniques", impact.evasionTechniques],
                        ["Attacker objectives", impact.attackerObjectives],
                      ]}
                    />
                  );
                })()}
                <KeyValueBlock
                  title="Kill Chain"
                  pairs={[
                    ["Attack chain", tech.attackChain],
                    ["Initial access", tech.initialAccess],
                    ["Privilege escalation", tech.privilegeEscalation],
                    ["Execution", tech.execution],
                    ["Persistence", tech.persistence],
                    ["Defense evasion", tech.defenseEvasion],
                    ["Lateral movement", tech.lateralMovement],
                    ["Command & control", tech.commandAndControl],
                    ["Data theft", tech.dataTheft],
                    ["Ransomware deployment", tech.ransomwareDeployment],
                  ]}
                />
                {report.mitreAttack.length > 0 && (
                  <div className="mt-3">
                    <h5 className="mb-1 text-xs font-semibold text-foreground">MITRE ATT&amp;CK Mapping</h5>
                    <div className="space-y-1.5">
                      {report.mitreAttack.map((t, i) => (
                        <div key={i} className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant="cyan" className="font-mono">
                              {t.techniqueId ?? "T????"}
                            </Badge>
                            <span className="font-semibold text-foreground">{t.technique}</span>
                            <span className="text-muted">· {t.killChainPhase}</span>
                            {t.confidence && (
                              <Badge variant={priorityVariant(t.confidence)} className="ml-auto">
                                {t.confidence} confidence
                              </Badge>
                            )}
                          </div>
                          <p className="mt-1 text-muted">{t.reason}</p>
                          {t.evidence && <p className="mt-1 border-l-2 border-white/10 pl-2 italic text-muted">Evidence: &ldquo;{t.evidence}&rdquo;</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {namedThreatActors.length > 0 && (
                  <div className="mt-3">
                    <h5 className="mb-1 text-xs font-semibold text-foreground">Threat Actors</h5>
                    <div className="space-y-2">
                      {namedThreatActors.map((a, i) => (
                        <div key={i} className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs">
                          <div className="font-semibold text-foreground">
                            {a.group}
                            {a.aliases.length > 0 && <span className="font-normal text-muted"> (aka {a.aliases.join(", ")})</span>}
                          </div>
                          <div className="mt-1 space-y-0.5 text-muted">
                            {a.motivation && <div>Motivation: {a.motivation}</div>}
                            {a.geography && <div>Geography: {a.geography}</div>}
                            {a.targetSectors.length > 0 && <div>Target sectors: {a.targetSectors.join(", ")}</div>}
                            {a.knownCampaigns.length > 0 && <div>Known campaigns: {a.knownCampaigns.join(", ")}</div>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {namedMalware.length > 0 && (
                  <div className="mt-3">
                    <h5 className="mb-1 text-xs font-semibold text-foreground">Malware</h5>
                    <div className="space-y-2">
                      {namedMalware.map((m, i) => (
                        <div key={i} className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs">
                          <div className="font-semibold text-foreground">{m.family}</div>
                          <div className="mt-1 space-y-0.5 text-muted">
                            {m.capabilities.length > 0 && <div>Capabilities: {m.capabilities.join(", ")}</div>}
                            {m.persistence && <div>Persistence: {m.persistence}</div>}
                            {m.payload && <div>Payload: {m.payload}</div>}
                            {m.deliveryMechanism && <div>Delivery: {m.deliveryMechanism}</div>}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {/* 5b. Intelligence Gaps -- "very useful": what we don't know yet,
              distinct from the Kill Chain block above it (which shows what
              IS known). Purely derived from fields the schema already
              leaves null when the article doesn't describe that stage -- no
              new AI generation, this is just a dedicated view surfacing an
              absence that was previously only visible by scanning the Kill
              Chain block for missing rows. */}
          {(() => {
            const tech = report.technicalAnalysis ?? EMPTY_TECHNICAL_ANALYSIS;
            const gaps = buildIntelligenceGaps(tech, report.malware);
            if (gaps.length === 0) return null;
            return (
              <Section title="Intelligence Gaps">
                <p className="mb-1.5 text-xs text-muted">Not described in this article -- absence of evidence, not evidence this stage didn't happen.</p>
                <div className="flex flex-wrap gap-1.5">
                  {gaps.map((g) => (
                    <Badge key={g} variant="muted">
                      Unknown: {g}
                    </Badge>
                  ))}
                </div>
              </Section>
            );
          })()}

          {/* 6. Top Actions & What's Missing. */}
          {(() => {
            const risk = report.businessRisk ?? EMPTY_BUSINESS_RISK;
            if ((risk.topActions?.length ?? 0) === 0 && !risk.whatsMissing) return null;
            return (
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Top Actions &amp; What's Missing</h4>
                <FieldList title="" items={risk.topActions ?? []} />
                {risk.whatsMissing && (
                  <div className="mt-2 text-xs text-muted">
                    <span className="font-semibold text-foreground">What's missing: </span>
                    {risk.whatsMissing}
                  </div>
                )}
              </div>
            );
          })()}

          {/* 7. IOCs -- CVEs shown alongside since both are the same
              "Vendor Confirmed Intelligence" category from the legend
              above, never model-generated. Always renders (not gated on
              totalIocs > 0) so a genuinely IOC-free article shows the
              explicit fallback line rather than the whole section silently
              vanishing. */}
          <Section title="Indicators of Compromise (verified, extracted from source text)">
            {report.cves.length > 0 && (
              <div className="mb-2.5 space-y-1.5">
                {report.cves.map((cve) => (
                  <a
                    key={cve.id}
                    href={cve.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex flex-wrap items-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs text-foreground hover:text-primary hover:underline"
                  >
                    <span className="font-mono font-semibold">{cve.id}</span>
                    <SeverityBadge severity={cve.severity as never} />
                    {cve.cvssScore != null && <span className="text-muted">CVSS {cve.cvssScore}</span>}
                    {cve.epssScore != null && <span className="text-muted">EPSS {(cve.epssScore * 100).toFixed(1)}%</span>}
                    {cve.knownExploited && <Badge variant="critical">KEV</Badge>}
                  </a>
                ))}
              </div>
            )}
            {totalIocs === 0 ? (
              <p className="text-sm text-muted">No Indicators of Compromise were published by the vendor.</p>
            ) : (
              <>
                {report.iocProvenance && (
                  <p className="mb-2.5 text-[11px] text-muted">
                    Every indicator below is {report.iocProvenance.confidence.toLowerCase()} -- extracted directly from{" "}
                    <a href={report.iocProvenance.sourceUrl} target="_blank" rel="noreferrer" className="underline hover:text-primary">
                      {report.iocProvenance.source}
                    </a>
                    's own text, never model-generated. Vendor confirmed. First seen {new Date(report.iocProvenance.firstSeen).toLocaleDateString()}.
                  </p>
                )}
                <div className="space-y-2.5">
                  <IocRow label="IP Addresses" values={report.iocs.ipAddresses} />
                  <IocRow label="Domains" values={report.iocs.domains} />
                  <IocRow label="URLs" values={report.iocs.urls} />
                  <IocRow label="Hashes" values={report.iocs.hashes} />
                  <IocRow label="Email Addresses" values={report.iocs.emailAddresses} />
                  <IocRow label="Registry Keys" values={report.iocs.registryKeys ?? []} />
                  <IocRow label="File Paths" values={report.iocs.filePaths ?? []} />
                  <IocRow label="File Names" values={report.iocs.fileNames ?? []} />
                  <IocRow label="Ports" values={report.iocs.ports ?? []} />
                  <IocRow label="Event IDs" values={report.iocs.eventIds ?? []} />
                  <IocRow label="Named Pipes" values={report.iocs.namedPipes ?? []} />
                  <IocRow label="Mutexes" values={report.iocs.mutexes ?? []} />
                  <IocRow label="Scheduled Tasks" values={report.iocs.scheduledTasks ?? []} />
                  <IocRow label="Services" values={report.iocs.services ?? []} />
                  <IocRow label="CWE IDs" values={report.iocs.cweIds ?? []} />
                  <IocRow label="CLI / PowerShell Commands" values={report.iocs.cliCommands ?? []} />
                  <IocRow label="User Agents" values={report.iocs.userAgents ?? []} />
                  <IocRow label="MITRE ATT&CK IDs (in article text)" values={report.iocs.attackTechniqueIds ?? []} />
                  <IocRow label="Malware Names (in article text)" values={report.iocs.malwareNames ?? []} />
                </div>
              </>
            )}
          </Section>

          {/* 7b. Infrastructure Reuse -- hunters care whether THIS report's
              indicators already showed up elsewhere this platform tracks.
              Computed live server-side (server/infrastructureReuse.js) by
              cross-referencing this report's own IOCs against every
              malware/actor/campaign entity and every other AI Summarization
              report -- real correlated data, never AI-generated, so this
              only renders when a genuine hit exists. No "Victims" row: this
              platform has no per-victim linkage for these IOCs, so rather
              than invent one, it's simply not shown. */}
          {(() => {
            const reuse = report.infrastructureReuse ?? EMPTY_INFRASTRUCTURE_REUSE;
            if (!reuse.hasReuse) return null;
            return (
              <Section title="Infrastructure Reuse">
                <KeyValueBlock
                  title=""
                  pairs={[
                    ["Threat actor(s)", reuse.threatActors.join(", ") || null],
                    ["Related malware", reuse.relatedMalwareFamilies.join(", ") || null],
                    ["Related campaign(s)", reuse.relatedCampaigns.join(", ") || null],
                  ]}
                />
                <div className="mt-2 space-y-1.5">
                  {reuse.matchedIndicators.map((m, i) => (
                    <div key={i} className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs">
                      <span className="font-mono font-semibold text-foreground">{m.indicator}</span>
                      <span className="ml-1.5 text-muted">({m.indicatorType})</span>
                      <div className="mt-1 space-y-0.5 text-muted">
                        {m.linkedMalwareFamilies.length > 0 && <div>Malware: {m.linkedMalwareFamilies.join(", ")}</div>}
                        {m.linkedThreatActors.length > 0 && <div>Threat actor: {m.linkedThreatActors.join(", ")}</div>}
                        {m.linkedCampaigns.length > 0 && <div>Campaign: {m.linkedCampaigns.join(", ")}</div>}
                        {m.seenInOtherReports.length > 0 && (
                          <div>
                            Also seen in:{" "}
                            {m.seenInOtherReports.map((r, j) => (
                              <a key={j} href={r.link} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                                {j > 0 ? ", " : ""}
                                {r.title}
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
                {reuse.timeline.length > 1 && (
                  <div className="mt-2">
                    <h5 className="mb-1 text-xs font-semibold text-foreground">Timeline</h5>
                    <ul className="space-y-1 text-xs">
                      {reuse.timeline.map((t, i) => (
                        <li key={i}>
                          <span className="text-muted">{new Date(t.date).toLocaleDateString()}: </span>
                          {t.link ? (
                            <a href={t.link} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                              {t.label}
                            </a>
                          ) : (
                            <span className="text-foreground">{t.label}</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </Section>
            );
          })()}

          {/* 8. Unified Operational Guidance -- one table replacing both the
              former flat "Operational Actions" priority table and the
              five separate per-team detailed-guidance blocks below it.
              See buildOperationalGuidanceRows for how each team's row is
              composed from operationalRecommendations (priority/action/
              rationale) plus that team's own operationalActions sub-object
              (detailed guidance/telemetry/detection opportunities/next
              steps) -- genuinely merged, not just visually adjacent. */}
          <OperationalGuidanceTable report={report} />

          {/* 10. Recommendations -- platform/tooling-specific guidance,
              distinct from the team-action table above ("what to do" vs.
              "which platform feature to configure"). */}
          {(() => {
            const actions = report.operationalActions ?? EMPTY_OPERATIONAL_ACTIONS;
            const platformRecs = actions.platformRecommendations ?? EMPTY_PLATFORM_RECOMMENDATIONS;
            // userRecommendations deliberately excluded -- it has its own
            // section further down now, so its presence alone shouldn't
            // render this heading with nothing under it.
            const { userRecommendations: _userRecs, ...securityTeamRecs } = platformRecs;
            if (Object.values(securityTeamRecs).every((list) => list.length === 0)) return null;
            return (
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Recommendations</h4>
                <GroupedLists
                  title=""
                  groups={[
                    ["Log sources to review", platformRecs.logSourcesToReview],
                    ["Microsoft Defender XDR", platformRecs.microsoftDefenderRecommendations],
                    ["Microsoft Sentinel", platformRecs.microsoftSentinelRecommendations],
                    ["Firewall / DNS", platformRecs.firewallDnsRecommendations],
                    ["Email security (Defender for Office 365)", platformRecs.emailSecurityRecommendations],
                    ["Identity monitoring", platformRecs.identityMonitoringRecommendations],
                    ["EDR", platformRecs.edrRecommendations],
                  ]}
                />
              </div>
            );
          })()}

          {/* 11. End User Recommendations -- its own section, deliberately
              last before Source, since it's addressed to a different
              audience (employees, not security staff) than everything
              above it. Only populated when the attack vector genuinely
              involves end-user action. */}
          {(() => {
            const userRecs = report.operationalActions?.platformRecommendations?.userRecommendations ?? [];
            if (userRecs.length === 0) return null;
            return (
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">End User Recommendations</h4>
                <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
                  {userRecs.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
            );
          })()}

          {/* 12. Source -- last, always. */}
          <div>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Source</h4>
            <ul className="space-y-1">
              {report.references.map((ref, i) => (
                <li key={i}>
                  <a href={ref.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-xs text-foreground hover:text-primary hover:underline">
                    {ref.label}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Enterprise-grade SOC threat intelligence reports generated by a local LLM
 * from major vendor threat-research and CISA advisories (Cisco Talos, Unit
 * 42, CrowdStrike, Microsoft Security, Google Threat Intelligence, Rapid7,
 * CISA, etc. -- see MAJOR_VENDOR_SOURCES in server/connectors/newsFeeds.js).
 * Facts (severity, CVEs, IOCs) are grounded in this app's own verified
 * extraction/enrichment, never trusted to the model's own recall -- only the
 * analytical fields (executive/business/threat narrative, detection/hunting/
 * IR guidance, the four role-based takeaways, confidence/risk scoring) are
 * the model's own synthesis. Currently generated only for Critical/High/
 * Medium severity articles -- Low is deliberately deferred, not dropped.
 * Runs one report at a time in the background (see
 * server/aiThreatSummaryJob.js), so this fills in gradually.
 */
const SEVERITY_FILTERS: Array<Severity | "all"> = ["all", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEVERITY_FILTER_LABEL: Record<Severity | "all", string> = {
  all: "All severities",
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNKNOWN: "Unknown",
};

interface AiSummarizationProps {
  /** Pre-fills the search box -- set from Pivot Chain's "Open Report" action when a report node is pivoted to. */
  initialQuery?: string | null;
}

export function AiSummarization({ initialQuery }: AiSummarizationProps = {}) {
  const { data, isLoading, isError, error } = useAiThreatSummaries();
  const [search, setSearch] = useState(initialQuery ?? "");

  useEffect(() => {
    if (initialQuery) setSearch(initialQuery);
  }, [initialQuery]);

  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [dateRange, setDateRange] = useState<DateRange>(EMPTY_DATE_RANGE);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const reports = data?.reports ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return reports.filter((r) => {
      if (severityFilter !== "all" && r.severity !== severityFilter) return false;
      // Filters by generatedAt (when the report itself appeared in this tab),
      // not publishedDate (when the underlying article came out) -- matches
      // the "just now"/"Nh ago" timestamp already shown on each row, so the
      // date picker answers the same question the row itself is showing.
      if (!isWithinDateRange(r.generatedAt, dateRange)) return false;
      if (!q) return true;
      return (
        r.articleTitle.toLowerCase().includes(q) ||
        r.cves.some((c) => c.id.toLowerCase().includes(q)) ||
        r.threatActors.some((a) => a.group.toLowerCase().includes(q)) ||
        r.malware.some((m) => m.family.toLowerCase().includes(q)) ||
        (r.campaignName?.toLowerCase().includes(q) ?? false)
      );
    });
  }, [reports, search, severityFilter, dateRange]);

  function toggle(id: string) {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const criticalCount = reports.filter((r) => r.severity === "CRITICAL").length;

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3">
        <div>
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <BrainCircuit className="h-4 w-4 text-primary" />
            AI Summarization{" "}
            <span className="font-normal text-muted">
              ({reports.length} report{reports.length === 1 ? "" : "s"}, {criticalCount} critical)
            </span>
          </CardTitle>
          <p className="mt-1 text-xs text-muted">
            Critical/High/Medium vendor advisories and CISA alerts converted into full enterprise SOC intelligence reports -- executive/business/threat analysis, MITRE mapping, detection &amp; hunting
            guidance across major platforms, IR guidance, and role-based takeaways, not a news recap.
          </p>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2">
          <Input placeholder="Search by title, CVE, actor, or malware…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full sm:w-72" />
          <Select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as Severity | "all")} className="w-full sm:w-40">
            {SEVERITY_FILTERS.map((s) => (
              <option key={s} value={s}>
                {SEVERITY_FILTER_LABEL[s]}
              </option>
            ))}
          </Select>
          <DateRangeFilter value={dateRange} onChange={setDateRange} />
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : isError && reports.length === 0 ? (
          // Only show the error state when there's truly nothing to show --
          // a background refetch (this tab polls every few minutes) failing
          // once (a restart, a transient network blip) must not hide reports
          // already sitting in cache. Confirmed live this was happening:
          // isError alone used to gate this branch, so a single failed
          // refetch replaced a real, populated report list with an error
          // screen even though `data` from the last successful fetch was
          // still valid and unchanged.
          <ErrorState message={error?.message ?? "AI Summarization is unavailable right now."} />
        ) : filtered.length === 0 ? (
          <EmptyState
            message={
              reports.length === 0
                ? "No reports generated yet -- summarization runs one Critical/High/Medium vendor/CISA article at a time in the background; check back shortly."
                : "No reports match this search/severity/date filter."
            }
          />
        ) : (
          <div className="space-y-2">
            {filtered.map((report) => (
              <ReportRow key={report.id} report={report} expanded={expandedIds.has(report.id)} onToggle={() => toggle(report.id)} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
