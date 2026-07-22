import { useMemo, useState } from "react";
import { BrainCircuit, ChevronDown, ChevronRight, ExternalLink, ShieldAlert, Gauge, FileDown, FileType } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { SeverityBadge } from "./SeverityBadge";
import { DateRangeFilter, EMPTY_DATE_RANGE, isWithinDateRange, type DateRange } from "./DateRangeFilter";
import { useAiThreatSummaries } from "@/hooks/useAiThreatSummaries";
import type { AiThreatSummaryReport, Severity } from "@/types/threat-intel";
import { cn } from "@/lib/utils";
import { downloadReportAsPdf, downloadReportAsWord } from "@/lib/reportExport";

// Reports generated before the aiTechnicalSummary field existed (superseding
// the old flat aiSummarizationBullets) won't have it at all -- falls back to
// all-empty rather than crashing on report.aiTechnicalSummary.threat etc.
const EMPTY_TECHNICAL_SUMMARY = {
  threat: [],
  attackVector: [],
  rootCause: [],
  exploitationDetails: [],
  technicalFindings: [],
  securityImplications: [],
  detectionOpportunities: [],
  huntingOpportunities: [],
  immediateActions: [],
};

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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">{title}</h4>
      {children}
    </div>
  );
}

function FieldList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <Section title={title}>
      <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
        {items.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </ul>
    </Section>
  );
}

/** label: value pairs where value is a plain string, skipping "Not Reported" entries so the card isn't padded with filler. */
function KeyValueBlock({ title, pairs }: { title: string; pairs: Array<[string, string | null]> }) {
  const shown = pairs.filter(([, v]) => v && v !== "Not Reported");
  if (shown.length === 0) return null;
  return (
    <Section title={title}>
      <dl className="space-y-1.5 text-sm">
        {shown.map(([label, value]) => (
          <div key={label}>
            <dt className="inline font-semibold text-foreground">{label}: </dt>
            <dd className="inline text-foreground">{value}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

/** Groups of string[] keyed by a human label, e.g. per-platform hunting queries -- renders code-styled entries, skips empty groups entirely. */
function GroupedCodeLists({ title, groups }: { title: string; groups: Array<[string, string[]]> }) {
  const nonEmpty = groups.filter(([, items]) => items.length > 0);
  if (nonEmpty.length === 0) return null;
  return (
    <Section title={title}>
      <div className="space-y-3">
        {nonEmpty.map(([label, items]) => (
          <div key={label}>
            <div className="mb-1 text-xs font-semibold text-foreground">{label}</div>
            <ul className="space-y-1">
              {items.map((item, i) => (
                <li key={i} className="rounded-md border border-white/[0.06] bg-black/20 px-2 py-1 font-mono text-xs text-foreground">
                  {item}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}

function GroupedLists({ title, groups }: { title: string; groups: Array<[string, string[]]> }) {
  const nonEmpty = groups.filter(([, items]) => items.length > 0);
  if (nonEmpty.length === 0) return null;
  return (
    <Section title={title}>
      <div className="space-y-2.5">
        {nonEmpty.map(([label, items]) => (
          <div key={label}>
            <div className="mb-1 text-xs font-semibold text-foreground">{label}</div>
            <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
              {items.map((item, i) => (
                <li key={i}>{item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
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

function ReportRow({ report, expanded, onToggle }: { report: AiThreatSummaryReport; expanded: boolean; onToggle: () => void }) {
  const kevCount = report.cves.filter((c) => c.knownExploited).length;
  const totalIocs = report.iocs.ipAddresses.length + report.iocs.domains.length + report.iocs.urls.length + report.iocs.hashes.length + report.iocs.emailAddresses.length;
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
              <Badge variant={priorityVariant(report.aiRiskScoring.priority)} title={`AI-computed risk score: ${report.aiRiskScoring.score ?? "—"}/100. See "AI Risk Score" below for the reasoning.`}>
                {report.aiRiskScoring.priority} priority
              </Badge>
              {kevCount > 0 && (
                <Badge variant="critical" className="gap-1">
                  <ShieldAlert className="h-3 w-3" />
                  {kevCount} KEV
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
          <div>
            <div className="flex flex-wrap gap-2">
              <ScoreGauge label="AI Risk Score" value={report.aiRiskScoring.score == null ? "—" : `${report.aiRiskScoring.score}/100`} variant={priorityVariant(report.aiRiskScoring.priority)} />
              <ScoreGauge
                label="Analysis Confidence"
                value={report.confidenceAssessment.level}
                variant={report.confidenceAssessment.level === "High" ? "low" : report.confidenceAssessment.level === "Medium" ? "medium" : "high"}
                title={`Why ${report.confidenceAssessment.level}: ${report.confidenceAssessment.reasoning}`}
              />
            </div>
            {/* Confirmed live this reads as a contradiction otherwise -- "Confidence" sits right next to a risk/priority score, so a reader assumes it's on the same severity scale. It isn't: it's the model's own certainty that *this report* accurately reflects the source article, completely independent of how severe the underlying threat is. "Medium priority, High confidence" means "I'm quite sure this really is Medium," not "actually High." */}
            <p className="mt-1.5 text-[11px] text-muted">Analysis Confidence is the model's certainty that this report reflects the source article -- not a severity signal. See "Overall SOC priority" below for the vendor-context assessment.</p>
          </div>

          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Executive Summary</h4>
            <p className="text-foreground">{report.executiveSummary}</p>
          </div>

          <GroupedLists
            title="AI Technical Summary"
            groups={(() => {
              const summary = report.aiTechnicalSummary ?? EMPTY_TECHNICAL_SUMMARY;
              return [
                ["Threat", summary.threat],
                ["Attack Vector", summary.attackVector],
                ["Root Cause", summary.rootCause],
                ["Exploitation Details", summary.exploitationDetails],
                ["Technical Findings", summary.technicalFindings],
                ["Security Implications", summary.securityImplications],
                ["Detection Opportunities", summary.detectionOpportunities],
                ["Hunting Opportunities", summary.huntingOpportunities],
                ["Immediate Actions", summary.immediateActions],
              ] as Array<[string, string[]]>;
            })()}
          />

          <KeyValueBlock
            title="Business Impact"
            pairs={[
              ["Business risk", report.businessImpact.businessRisk],
              ["Operational disruption", report.businessImpact.operationalDisruption],
              ["Likelihood of exploitation", report.businessImpact.likelihoodOfExploitation],
              ["Impact if unpatched", report.businessImpact.impactIfUnpatched],
            ]}
          />
          {(() => {
            const industries = report.businessImpact.industriesCommonlyTargeted ?? [];
            const regions = report.businessImpact.regionsCommonlyTargeted ?? [];
            if (industries.length === 0 && regions.length === 0) return null;
            return (
              <div className="-mt-3 space-y-0.5 text-xs text-muted">
                {industries.length > 0 && <div>Industries commonly targeted: {industries.join(", ")}</div>}
                {regions.length > 0 && <div>Regions impacted: {regions.join(", ")}</div>}
              </div>
            );
          })()}

          <KeyValueBlock
            title="Threat Overview"
            pairs={[
              ["Attack chain", report.threatOverview.attackChain],
              ["Initial access", report.threatOverview.initialAccess],
              ["Privilege escalation", report.threatOverview.privilegeEscalation],
              ["Execution", report.threatOverview.execution],
              ["Persistence", report.threatOverview.persistence],
              ["Defense evasion", report.threatOverview.defenseEvasion],
              ["Lateral movement", report.threatOverview.lateralMovement],
              ["Command & control", report.threatOverview.commandAndControl],
              ["Data theft", report.threatOverview.dataTheft],
              ["Ransomware deployment", report.threatOverview.ransomwareDeployment],
            ]}
          />

          <GroupedLists
            title="Affected Products"
            groups={[
              ["Products", report.affectedProducts.products],
              ["Versions", report.affectedProducts.versions],
              ["Operating systems", report.affectedProducts.operatingSystems],
              ["Cloud services", report.affectedProducts.cloudServices],
              ["Applications", report.affectedProducts.applications],
            ]}
          />

          <KeyValueBlock
            title="Severity Assessment"
            pairs={[
              ["Vendor severity", report.vendorSeverityAssessment.vendorSeverity],
              ["Active exploitation", report.vendorSeverityAssessment.activeExploitation],
              ["Overall SOC priority", report.vendorSeverityAssessment.overallSocPriority],
            ]}
          />

          {report.cves.length > 0 && (
            <Section title="CVEs (verified CVSS/EPSS/KEV)">
              <div className="space-y-1.5">
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
            </Section>
          )}

          {report.mitreAttack.length > 0 && (
            <Section title="MITRE ATT&CK Mapping">
              <div className="space-y-1.5">
                {report.mitreAttack.map((t, i) => (
                  <div key={i} className="rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-1.5 text-xs">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="cyan" className="font-mono">
                        {t.techniqueId ?? "T????"}
                      </Badge>
                      <span className="font-semibold text-foreground">{t.technique}</span>
                      <span className="text-muted">· {t.killChainPhase}</span>
                    </div>
                    <p className="mt-1 text-muted">{t.reason}</p>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {namedThreatActors.length > 0 && (
            <Section title="Threat Actors">
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
            </Section>
          )}

          {namedMalware.length > 0 && (
            <Section title="Malware">
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
            </Section>
          )}

          {totalIocs > 0 && (
            <Section title="Indicators of Compromise (verified, extracted from source text)">
              <div className="space-y-2.5">
                <IocRow label="IP Addresses" values={report.iocs.ipAddresses} />
                <IocRow label="Domains" values={report.iocs.domains} />
                <IocRow label="URLs" values={report.iocs.urls} />
                <IocRow label="Hashes" values={report.iocs.hashes} />
                <IocRow label="Email Addresses" values={report.iocs.emailAddresses} />
              </div>
            </Section>
          )}

          <FieldList title="Detection Opportunities" items={report.detectionOpportunities} />

          <GroupedCodeLists
            title="Threat Hunting Opportunities"
            groups={[
              ["Microsoft Defender XDR (KQL)", report.threatHuntingOpportunities.defenderXdrKql],
              ["Microsoft Sentinel (KQL)", report.threatHuntingOpportunities.sentinelKql],
              ["Splunk (SPL)", report.threatHuntingOpportunities.splunkSpl],
              ["Elastic", report.threatHuntingOpportunities.elastic],
              ["Sigma", report.threatHuntingOpportunities.sigma],
              ["YARA", report.threatHuntingOpportunities.yara],
              ["CrowdStrike Falcon", report.threatHuntingOpportunities.crowdstrikeFalcon],
              ["Carbon Black", report.threatHuntingOpportunities.carbonBlack],
            ]}
          />

          <GroupedLists
            title="Detection Engineering Opportunities"
            groups={[
              ["New analytics", report.detectionEngineeringOpportunities.newAnalytics],
              ["New correlation rules", report.detectionEngineeringOpportunities.newCorrelationRules],
              ["New Sigma rules", report.detectionEngineeringOpportunities.newSigmaRules],
              ["New KQL detections", report.detectionEngineeringOpportunities.newKqlDetections],
              ["EDR behavioral detections", report.detectionEngineeringOpportunities.edrBehavioralDetections],
              ["SIEM correlation logic", report.detectionEngineeringOpportunities.siemCorrelationLogic],
              ["MITRE coverage gaps", report.detectionEngineeringOpportunities.mitreCoverageGaps],
              ["Telemetry gaps", report.detectionEngineeringOpportunities.telemetryGaps],
              ["Log source requirements", report.detectionEngineeringOpportunities.logSourceRequirements],
            ]}
          />

          <GroupedLists
            title="Incident Response Guidance"
            groups={[
              ["Immediate triage steps", report.incidentResponseGuidance.immediateTriageSteps],
              ["Evidence to collect", report.incidentResponseGuidance.evidenceToCollect],
              ["Containment actions", report.incidentResponseGuidance.containmentActions],
              ["Forensic artifacts", report.incidentResponseGuidance.forensicArtifacts],
              ["Recovery actions", report.incidentResponseGuidance.recoveryActions],
              ["Validation steps", report.incidentResponseGuidance.validationSteps],
            ]}
          />

          <GroupedLists
            title="Immediate Recommendations"
            groups={[
              ["Critical", report.immediateRecommendations.critical],
              ["High", report.immediateRecommendations.high],
              ["Medium", report.immediateRecommendations.medium],
              ["Low", report.immediateRecommendations.low],
            ]}
          />

          <GroupedLists
            title="Patch Information"
            groups={[
              ["Fixed versions", report.patchInformationNarrative.fixedVersions],
              ["Temporary mitigations", report.patchInformationNarrative.temporaryMitigations],
              ["Known workarounds", report.patchInformationNarrative.knownWorkarounds],
            ]}
          />
          {(report.patchInformationNarrative.availability !== "Not Reported" || report.patchInformationNarrative.vendorGuidance) && (
            <div className="-mt-3 space-y-0.5 text-xs text-muted">
              {report.patchInformationNarrative.availability !== "Not Reported" && <div>Availability: {report.patchInformationNarrative.availability}</div>}
              {report.patchInformationNarrative.vendorGuidance && <div>Vendor guidance: {report.patchInformationNarrative.vendorGuidance}</div>}
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">SOC Analyst Takeaway</h4>
              <p className="text-foreground">{report.socAnalystTakeaway}</p>
            </div>
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Detection Engineer Takeaway</h4>
              <p className="text-foreground">{report.detectionEngineerTakeaway}</p>
            </div>
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Threat Hunter Takeaway</h4>
              <p className="text-foreground">{report.threatHunterTakeaway}</p>
            </div>
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Threat Intel Takeaway</h4>
              <p className="text-foreground">{report.threatIntelTakeaway}</p>
            </div>
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Executive Leadership Takeaway</h4>
              <p className="text-foreground">{report.executiveLeadershipTakeaway}</p>
            </div>
            {report.cves.length > 0 && report.vulnerabilityManagementTakeaway && report.vulnerabilityManagementTakeaway !== "Not Applicable" && (
              <div>
                <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Vulnerability Management Takeaway</h4>
                <p className="text-foreground">{report.vulnerabilityManagementTakeaway}</p>
              </div>
            )}
          </div>

          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Confidence & Risk Reasoning</h4>
            <p className="text-xs text-muted">
              <span className="font-semibold text-foreground">Confidence ({report.confidenceAssessment.level}):</span> {report.confidenceAssessment.reasoning}
            </p>
            <p className="mt-1 text-xs text-muted">
              <span className="font-semibold text-foreground">Risk score reasoning:</span> {report.aiRiskScoring.reasoning}
            </p>
          </div>

          <div>
            <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">References</h4>
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

export function AiSummarization() {
  const { data, isLoading, isError, error } = useAiThreatSummaries();
  const [search, setSearch] = useState("");
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
        r.malware.some((m) => m.family.toLowerCase().includes(q))
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
        ) : isError ? (
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
