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
import { CorrelationSummaryPanel } from "./investigation/CorrelationSummaryPanel";
import { SearchCoveragePanel } from "./investigation/SearchCoveragePanel";
import { EvidencePanel } from "./investigation/EvidencePanel";
import { InvestigationGraph } from "./InvestigationGraph";
import { useSelection } from "@/context/SelectionContext";
import { useGenerateInvestigationAiReport } from "@/hooks/useInvestigate";
import { useInvestigationWorkspace } from "@/hooks/useInvestigationWorkspace";
import { sectionFamilyFor, INDICATOR_TYPE_LABEL } from "@/investigation/moduleConfig";
import { virusTotalLookupUrl } from "@/lib/vtLookup";
import type { IndicatorType, InvestigationResult, MalwareIntelligenceEntity, CveRecord, CveProfile, DetectionRuleRef, IocLookupResult, VerdictState } from "@/types/threat-intel";
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
          <div className="mt-2 space-y-1 rounded-lg border border-accent-cyan/20 bg-accent-cyan/[0.05] p-2">
            {verdict.conflicts.map((c, i) => (
              <p key={i} className="text-xs text-accent-cyan">
                {c}
              </p>
            ))}
          </div>
        )}
        <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
          <div>
            <span className="text-muted">Severity: </span>
            <span className="font-semibold text-foreground">{verdict.severity}</span>
          </div>
          <div>
            <span className="text-muted">Risk Level: </span>
            <span className="font-semibold text-foreground">{verdict.riskLevel}</span>
          </div>
          <div>
            <span className="text-muted">Recommended Priority: </span>
            <span className="font-semibold text-foreground">{verdict.recommendedPriority}</span>
          </div>
          <div>
            <span className="text-muted">Confidence: </span>
            <span className="font-semibold text-foreground">{verdict.confidence}</span>
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

/**
 * The verdict engine's own reasoning sentence (server/investigation/verdictEngine.js)
 * -- already names the real evidence-bearing sources/counts that produced
 * this verdict, so this section doesn't hand-pick its own subset of
 * evidence anymore (that used to cover only 5 hardcoded sources and could
 * drift from the actual verdict logic). Severity/risk/priority/confidence
 * are already on the Analyst Verdict tiles above; actor/campaign names are
 * already there too. Full per-source, per-category evidence lives in the
 * Evidence panel below. Each fact on this page lives in exactly one place;
 * this section only ever references other sections by name.
 */
function whyShouldICare(result: InvestigationResult): string[] {
  const overview = result.overview;
  const lines: string[] = [overview.verdict.reasoning];
  if (overview.associatedThreatActors.length > 0 || overview.activeCampaigns.length > 0) {
    lines.push("See the Analyst Verdict tiles above for linked actor(s)/campaign(s), and Relationships below for the full picture.");
  }
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
  const {
    investigateM,
    result,
    graphTarget,
    graphNode,
    recommendedActions,
    graphInsights,
    graphInsightsPending,
    graphInsightsError,
    correlationSummary,
    correlationSummaryPending,
    correlationSummaryError,
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

            <VerdictBanner overview={result.overview} />

            <SearchCoveragePanel coverage={result.coverage} />

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

            <CorrelationSummaryPanel summary={correlationSummary} pending={correlationSummaryPending} error={correlationSummaryError} onFocusEntity={runInvestigation} />

            <KeyFactsPanel facts={buildKeyFacts(result)} />

            <EvidencePanel evidence={result.overview.verdict.evidence} />

            <RelatedAiReportsSection result={result} />

            <RealDetectionsHuntingPanel graphNode={graphNode} />

            {recommendedActions && <RecommendedActionsPanel guidance={recommendedActions} />}

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
