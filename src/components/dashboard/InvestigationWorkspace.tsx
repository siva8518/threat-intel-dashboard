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
import { AiGraphInsightsPanel } from "./investigation/AiGraphInsightsPanel";
import { InvestigationGraph } from "./InvestigationGraph";
import { useSelection } from "@/context/SelectionContext";
import { useGenerateInvestigationAiReport } from "@/hooks/useInvestigate";
import { useInvestigationWorkspace } from "@/hooks/useInvestigationWorkspace";
import { sectionFamilyFor, INDICATOR_TYPE_LABEL } from "@/investigation/moduleConfig";
import { virusTotalLookupUrl } from "@/lib/vtLookup";
import type { IndicatorType, InvestigationResult, IocLookupResult, MalwareIntelligenceEntity, CveRecord, CveProfile, DetectionRuleRef } from "@/types/threat-intel";
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

const VERDICT_BADGE = { critical: "critical", high: "high", medium: "medium", low: "low", unknown: "muted" } as const;

function VerdictBanner({ overview }: { overview: InvestigationResult["overview"] }) {
  const level = overview.overallVerdict;
  const Icon = level === "critical" || level === "high" ? AlertTriangle : ShieldCheck;
  return (
    <div
      className={cn(
        "flex items-start gap-3 rounded-xl border p-4",
        level === "critical" && "border-critical/30 bg-critical/10",
        level === "high" && "border-high/30 bg-high/10",
        level === "medium" && "border-medium/30 bg-medium/10",
        level === "low" && "border-low/30 bg-low/10",
        level === "unknown" && "border-white/10 bg-white/[0.03]",
      )}
    >
      <Icon
        className={cn(
          "mt-0.5 h-5 w-5 shrink-0",
          level === "critical" && "text-critical",
          level === "high" && "text-high",
          level === "medium" && "text-medium",
          level === "low" && "text-low",
          level === "unknown" && "text-muted",
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={VERDICT_BADGE[level]}>{level.toUpperCase()}</Badge>
          <span className="text-sm font-semibold text-foreground">{overview.verdictLabel}</span>
        </div>
        <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
          <div>
            <span className="text-muted">Severity: </span>
            <span className="font-semibold text-foreground">{overview.severity}</span>
          </div>
          <div>
            <span className="text-muted">Risk Level: </span>
            <span className="font-semibold text-foreground">{overview.riskLevel}</span>
          </div>
          <div>
            <span className="text-muted">Recommended Priority: </span>
            <span className="font-semibold text-foreground">{overview.recommendedPriority}</span>
          </div>
          <div>
            <span className="text-muted">Confidence: </span>
            <span className="font-semibold text-foreground">{overview.confidence}</span>
          </div>
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
        {overview.mitreAttackMapping.length > 0 && (
          <p className="mt-2 text-xs text-muted">
            MITRE ATT&CK: <span className="font-mono text-foreground">{overview.mitreAttackMapping.map((t) => t.id).join(", ")}</span>
          </p>
        )}
      </div>
    </div>
  );
}

/** Concrete, cited evidence strings for ip/domain/url/hash types -- same source data buildKeyFacts() already reads, just phrased as evidence sentences instead of a label/value grid. Empty for a source that didn't fire or has nothing notable to report -- never a filler phrase. */
function concreteEvidence(result: InvestigationResult): string[] {
  const md = result.moduleData;
  const lookups = md.lookupResults as IocLookupResult[] | undefined;
  const find = (source: string) => lookups?.find((r) => r.source === source);
  const evidence: string[] = [];

  const abuseIpdb = find("AbuseIPDB");
  if (abuseIpdb && Number(abuseIpdb.totalReports) > 0) evidence.push(`${abuseIpdb.totalReports} AbuseIPDB report(s) at ${abuseIpdb.abuseConfidenceScore}% confidence`);

  const vt = find("VirusTotal");
  if (vt && Number(vt.malicious) > 0) evidence.push(`${vt.malicious} VirusTotal engine(s) flag it malicious${vt.threatLabel ? ` (${vt.threatLabel})` : ""}`);

  const pulsedive = find("Pulsedive");
  if (pulsedive && Array.isArray(pulsedive.threats) && pulsedive.threats.length > 0) evidence.push(`Pulsedive flags: ${(pulsedive.threats as string[]).join(", ")}`);

  const otx = find("OTX");
  if (otx && Number(otx.pulseCount) > 0) evidence.push(`present in ${otx.pulseCount} OTX threat pulse(s)`);

  const leakix = find("LeakIX");
  if (leakix && Number(leakix.leakCount) > 0) evidence.push(`${leakix.leakCount} exposed leak(s) via LeakIX`);

  const related = md.relatedIndicators as { sameCampaignOrActor?: unknown[]; sameAsn?: unknown[] } | undefined;
  if (related?.sameCampaignOrActor && related.sameCampaignOrActor.length > 0) evidence.push(`linked to ${related.sameCampaignOrActor.length} other indicator(s) in this platform's own tracked data`);

  return evidence;
}

/**
 * Evidence only -- severity/risk/priority/confidence are already on the
 * Analyst Verdict tiles directly above this, so nothing here repeats them.
 * Each fact on this page lives in exactly one place; later sections
 * reference it by name instead of restating the value.
 */
function whyShouldICare(result: InvestigationResult): string[] {
  const overview = result.overview;
  const evidence = concreteEvidence(result);
  const lines: string[] = [];
  if (evidence.length > 0) lines.push(`Evidence: ${evidence.join("; ")}.`);
  if (overview.associatedThreatActors.length > 0) lines.push(`Linked to tracked threat actor(s): ${overview.associatedThreatActors.join(", ")}.`);
  if (overview.activeCampaigns.length > 0) lines.push(`Associated with active campaign(s): ${overview.activeCampaigns.join(", ")}.`);
  if (lines.length === 0) lines.push("No further evidence beyond the verdict above -- no configured source or internal data adds anything on this indicator yet.");
  return lines;
}

function safe(v: unknown): string {
  return v == null || v === "" ? "—" : String(v);
}

interface KeyFact {
  label: string;
  value: string;
}

/** A compact "so what" summary distinct from the deeper Indicator-Specific Intelligence panels below it. */
function buildKeyFacts(result: InvestigationResult): KeyFact[] {
  const facts: KeyFact[] = [];
  const md = result.moduleData;
  const find = (source: string) => (md.lookupResults as IocLookupResult[] | undefined)?.find((r) => r.source === source);

  if (result.type === "ip") {
    const abuseIpdb = find("AbuseIPDB");
    const shodan = find("Shodan");
    const network = md.network as Record<string, unknown> | undefined;
    if (network?.country) facts.push({ label: "Country", value: safe(network.country) });
    if (network?.organization) facts.push({ label: "Organization", value: safe(network.organization) });
    if (abuseIpdb) facts.push({ label: "Abuse Reports", value: `${abuseIpdb.abuseConfidenceScore}% confidence` });
    if (shodan && Array.isArray(shodan.openPorts) && shodan.openPorts.length > 0) facts.push({ label: "Open Ports", value: (shodan.openPorts as number[]).slice(0, 8).join(", ") });
  } else if (result.type === "domain") {
    const reg = md.registration as Record<string, unknown> | null;
    const cert = find("crt.sh");
    if (reg?.registrar) facts.push({ label: "Registrar", value: safe(reg.registrar) });
    if (cert) facts.push({ label: "Subdomains Found", value: safe(cert.subdomainCount) });
    const security = md.security as Record<string, Record<string, unknown>> | undefined;
    if (security?.typosquatting?.flagged) facts.push({ label: "Typosquat Risk", value: `Resembles "${security.typosquatting.closestBrandMatch}"` });
  } else if (result.type === "url") {
    const scan = md.scan as Record<string, unknown> | null;
    const components = md.components as Record<string, unknown> | undefined;
    if (components?.host) facts.push({ label: "Host", value: safe(components.host) });
    if (scan && !scan.notScanned) facts.push({ label: "urlscan.io Classification", value: scan.malicious ? "Malicious" : "No malicious classification" });
  } else if (result.type === "sha256" || result.type === "sha1" || result.type === "md5") {
    const detection = md.detection as Record<string, unknown> | null;
    if (detection) facts.push({ label: "VirusTotal Detections", value: `${detection.malicious} / ${(detection.malicious as number) + (detection.suspicious as number) + (detection.harmless as number)}` });
    if (md.malwareFamily) facts.push({ label: "Malware Family", value: String(md.malwareFamily) });
  } else if (result.type === "cve") {
    const cve = md.cve as CveRecord | null;
    if (cve) {
      facts.push({ label: "CVSS", value: safe(cve.cvssScore) });
      facts.push({ label: "Known Exploited (KEV)", value: cve.knownExploited ? "Yes" : "No" });
    }
  } else if (result.type === "name") {
    facts.push({ label: "Matches Found", value: safe(md.total) });
  }

  return facts;
}

function KeyFactsPanel({ facts }: { facts: KeyFact[] }) {
  if (facts.length === 0) return null;
  return (
    <Section title="Key Facts">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        {facts.map((f) => (
          <div key={f.label} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
            <p className="text-[10px] uppercase tracking-wide text-muted">{f.label}</p>
            <p className="mt-0.5 text-xs font-semibold text-foreground" title={f.value}>
              {f.value}
            </p>
          </div>
        ))}
      </div>
    </Section>
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
 * name rather than restating it (see whyShouldICare()'s comment for the
 * concrete example).
 *
 * Page order front-loads synthesis before raw evidence: AI Summary (opt-in)
 * -> Verdict -> Why Should I Care -> Investigation Graph -> AI Investigation
 * Summary -> Key Facts -> AI/vendor reports -> real Detections & Hunting ->
 * Recommended Actions (SOC/Detection Engineering/Threat Intelligence/
 * Incident Response) -> Indicator-Specific raw lookup evidence -> deeper
 * opt-in AI narrative -> Quick Actions.
 */
export function InvestigationWorkspace({ onOpenActor, onOpenCampaign, goToCampaignSearch, goToMalwareSearch, goToAiSummarySearch, initialQuery }: WorkspaceProps) {
  const [input, setInput] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState<string | null>(null);
  const { selectCve, selectMalware } = useSelection();

  const workspace = useInvestigationWorkspace();
  const aiReportM = useGenerateInvestigationAiReport();
  const { investigateM, result, graphTarget, graphNode, recommendedActions, graphInsights, graphInsightsPending, graphInsightsError } = workspace;

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
          Paste anything from an alert — an IP, domain, URL, file hash, CVE ID, email, file/process name, registry key, user agent, or a malware/actor/campaign
          name — and get a complete investigation briefing instead of a raw source dump. Type is auto-detected, no manual selection needed.
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
            placeholder="e.g. CVE-2026-31431, 185.220.101.5, evil-domain.com, a1b2c3…, LockBit, phishing@evil.com"
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
            </p>

            <VerdictBanner overview={result.overview} />

            <Section title="Should I Care?">
              <div className="space-y-1.5">
                {whyShouldICare(result).map((line, i) => (
                  <p key={i} className="text-sm text-foreground">
                    {line}
                  </p>
                ))}
              </div>
            </Section>

            {/*
              The Investigation Graph is the primary relationship view on this
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
                goToTriageInvestigate={runInvestigation}
                goToCampaignSearch={goToCampaignSearch}
                goToMalwareSearch={goToMalwareSearch}
                goToActorSearch={onOpenActor}
                goToAiSummarySearch={goToAiSummarySearch}
                overview={result.overview}
              />
            )}

            <AiGraphInsightsPanel insights={graphInsights} pending={graphInsightsPending} error={graphInsightsError} onFocusEntity={runInvestigation} />

            <KeyFactsPanel facts={buildKeyFacts(result)} />

            <RelatedAiReportsSection result={result} />

            <RealDetectionsHuntingPanel graphNode={graphNode} />

            {recommendedActions && <RecommendedActionsPanel actions={recommendedActions} />}

            <Section title="Indicator-Specific Intelligence">
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
                  query={result.indicator}
                  data={result.moduleData as unknown as Parameters<typeof EntityIntelligenceSection>[0]["data"]}
                  onOpenMalware={openMalware}
                  onOpenActor={onOpenActor}
                  onOpenCampaign={onOpenCampaign}
                />
              )}
              {family === "artifact" && (
                <ArtifactIntelligenceSection note={result.moduleData.note as string} crossReference={result.relatedIntelligence!} />
              )}
            </Section>

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
