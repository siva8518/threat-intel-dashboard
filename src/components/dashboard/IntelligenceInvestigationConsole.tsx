import { useState } from "react";
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
import { useSelection } from "@/context/SelectionContext";
import { useInvestigate, useGenerateInvestigationAiReport } from "@/hooks/useInvestigate";
import { sectionFamilyFor, INDICATOR_TYPE_LABEL } from "@/investigation/moduleConfig";
import { virusTotalLookupUrl } from "@/lib/vtLookup";
import type {
  IndicatorType,
  InvestigationResult,
  IocLookupResult,
  MalwareIntelligenceEntity,
  CveRecord,
  CveProfile,
  DetectionRuleRef,
  PivotNodeType,
} from "@/types/threat-intel";
import { cn } from "@/lib/utils";

interface ConsoleProps {
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
  onOpenPivotChain: (type: PivotNodeType, key: string) => void;
}

/** Only ip/domain/cve map 1:1 onto a Pivot Chain node type -- name/hash/artifact types are ambiguous or out of the chain's scope, so no Pivot Chain entry point is offered for those. */
function pivotNodeTypeFor(type: IndicatorType): PivotNodeType | null {
  if (type === "ip" || type === "domain" || type === "cve") return type;
  return null;
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

function whyShouldICare(overview: InvestigationResult["overview"]): string {
  const parts = [`This indicator is currently rated ${overview.severity} severity with ${overview.riskLevel.toLowerCase()} risk (${overview.verdictLabel}).`];
  parts.push(`Recommended priority: ${overview.recommendedPriority}.`);
  if (overview.associatedThreatActors.length > 0) parts.push(`Linked to tracked threat actor(s): ${overview.associatedThreatActors.join(", ")}.`);
  if (overview.activeCampaigns.length > 0) parts.push(`Associated with active campaign(s): ${overview.activeCampaigns.join(", ")}.`);
  if (overview.overallVerdict === "unknown") parts.push("No configured source or internal data has meaningful signal on this indicator yet.");
  return parts.join(" ");
}

function safe(v: unknown): string {
  return v == null || v === "" ? "—" : String(v);
}

interface KeyFact {
  label: string;
  value: string;
}

/** A compact "so what" summary distinct from the deeper Indicator-Specific Intelligence panels below it -- same purpose TriageConsole.tsx's buildKeyFacts served, extended to the full 16-type surface. */
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
    if (security?.typosquatting?.flagged) facts.push({ label: "Typosquat Risk", value: `Resembles “${security.typosquatting.closestBrandMatch}”` });
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

function RelatedIntelligenceSection({
  result,
  onOpenActor,
  onOpenCampaign,
  onOpenPivotChain,
}: {
  result: InvestigationResult;
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
  onOpenPivotChain: (type: PivotNodeType, key: string) => void;
}) {
  const rel = result.relatedIntelligence;
  const pivotType = pivotNodeTypeFor(result.type);
  const pivotButton = pivotType && (
    <button
      type="button"
      onClick={() => onOpenPivotChain(pivotType, result.indicator)}
      className="mb-2 inline-flex items-center gap-1 rounded-lg border border-primary/30 bg-primary/10 px-2.5 py-1 text-xs text-primary hover:border-primary/50"
    >
      Walk Pivot Chain from here →
    </button>
  );
  if (!rel) {
    return pivotButton ? (
      <Section title="Related Intelligence">{pivotButton}</Section>
    ) : null;
  }
  const hasAny = rel.matchedMalwareFamilies.length > 0 || rel.associatedThreatActors.length > 0 || rel.activeCampaigns.length > 0 || rel.matchingAiReports.length > 0 || rel.relatedIocs.length > 0;
  if (!hasAny) {
    return (
      <Section title="Related Intelligence">
        {pivotButton}
        <p className="text-xs text-muted">No related intelligence found in this platform's own tracked data.</p>
      </Section>
    );
  }
  return (
    <Section title="Related Intelligence">
      <div className="space-y-3 text-xs">
        {pivotButton}
        {rel.matchedMalwareFamilies.length > 0 && (
          <p>
            <span className="font-semibold text-foreground">Malware Families: </span>
            <span className="text-muted">{rel.matchedMalwareFamilies.join(", ")}</span>
          </p>
        )}
        {rel.associatedThreatActors.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-semibold text-foreground">Threat Actors:</span>
            {rel.associatedThreatActors.map((name) => (
              <button key={name} type="button" onClick={() => onOpenActor(name)} className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary hover:border-primary/50">
                {name} →
              </button>
            ))}
          </div>
        )}
        {rel.activeCampaigns.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-semibold text-foreground">Campaigns:</span>
            {rel.activeCampaigns.map((name) => (
              <button key={name} type="button" onClick={onOpenCampaign} className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-primary hover:border-primary/50">
                {name} →
              </button>
            ))}
          </div>
        )}
        {rel.matchingAiReports.length > 0 && (
          <div>
            <p className="mb-1 font-semibold text-foreground">Related AI Summarization Reports:</p>
            <ul className="space-y-1">
              {rel.matchingAiReports.map((r) => (
                <li key={r.id}>
                  <a href={r.articleLink} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                    {r.articleTitle} <ExternalLink className="h-3 w-3" />
                  </a>{" "}
                  <span className="text-muted">— {r.articleSource}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
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
 * The Intelligence Investigation Console -- replaces TriageConsole.tsx.
 * Auto-detects all 16 indicator types server-side (no manual type
 * selection), leads with an answer (verdict/severity/priority/"why should I
 * care") instead of a raw source dump, and adds per-type investigation
 * modules plus an on-demand AI Investigation Report. Page order matches the
 * spec exactly: AI Summary -> Verdict -> Why Should I Care -> Key Facts ->
 * Indicator-Specific Intelligence -> Related Intelligence -> Detection
 * Opportunities -> Operational Guidance -> Raw Sources.
 */
export function IntelligenceInvestigationConsole({ onOpenActor, onOpenCampaign, onOpenPivotChain }: ConsoleProps) {
  const [input, setInput] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState<string | null>(null);
  const { selectCve, selectMalware } = useSelection();

  const investigateM = useInvestigate();
  const aiReportM = useGenerateInvestigationAiReport();

  function runInvestigation(raw: string) {
    const query = raw.trim();
    if (!query) return;
    setSubmittedQuery(query);
    investigateM.mutate(query);
    aiReportM.reset();
  }

  function openMalware(entity: MalwareIntelligenceEntity, detectionRules: DetectionRuleRef[]) {
    selectMalware({ family: entity.name, count: entity.iocSightings, sources: entity.articles.map((a) => a.source), techniques: [], detectionRules });
  }

  const result = investigateM.data;
  const family = result ? sectionFamilyFor(result.type as IndicatorType) : null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">Triage Console</CardTitle>
        <p className="mt-1 text-xs text-muted">
          Paste anything from an alert — an IP, domain, URL, file hash, CVE ID, email, file/process name, registry key, user agent, or a malware/actor/campaign
          name — and get a full investigation instead of a raw source dump. Type is auto-detected, no manual selection needed.
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

            <AiSummaryPanel
              report={aiReportM.data}
              isPending={aiReportM.isPending}
              error={aiReportM.isError ? (aiReportM.error as Error).message : null}
              onGenerate={() => aiReportM.mutate(submittedQuery)}
            />

            <VerdictBanner overview={result.overview} />

            <Section title="Should I Care?">
              <p className="text-sm text-foreground">{whyShouldICare(result.overview)}</p>
            </Section>

            <KeyFactsPanel facts={buildKeyFacts(result)} />

            <Section title="Indicator-Specific Intelligence">
              {family === "network" && result.type === "ip" && <IpIntelligenceSection data={result.moduleData as unknown as Parameters<typeof IpIntelligenceSection>[0]["data"]} />}
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

            <RelatedIntelligenceSection result={result} onOpenActor={onOpenActor} onOpenCampaign={onOpenCampaign} onOpenPivotChain={onOpenPivotChain} />

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
