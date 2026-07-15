import { useMemo, useState } from "react";
import { BrainCircuit, ChevronDown, ChevronRight, ExternalLink, ShieldAlert, Gauge } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { SeverityBadge } from "./SeverityBadge";
import { useAiThreatSummaries } from "@/hooks/useAiThreatSummaries";
import type { AiThreatSummaryReport } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

function timeAgo(iso: string) {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / (60 * 60 * 1000));
  if (hours < 1) return "just now";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function riskVariant(score: number | null): "critical" | "high" | "medium" | "low" | "muted" {
  if (score == null) return "muted";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function ScoreGauge({ label, score, icon }: { label: string; score: number | null; icon: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2">
      {icon}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted">{label}</div>
        <div className="text-sm font-semibold text-foreground">{score == null ? "—" : `${score}/100`}</div>
      </div>
    </div>
  );
}

function FieldList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">{title}</h4>
      <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
        {items.map((item, i) => (
          <li key={i}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function ReportRow({ report, expanded, onToggle }: { report: AiThreatSummaryReport; expanded: boolean; onToggle: () => void }) {
  const kevCount = report.cves.filter((c) => c.knownExploited).length;

  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02]">
      <button type="button" onClick={onToggle} className="flex w-full items-start justify-between gap-3 p-3 text-left">
        <div className="flex min-w-0 items-start gap-2">
          {expanded ? <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-muted" /> : <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-muted" />}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-foreground">{report.articleTitle}</span>
              <SeverityBadge severity={report.severity} />
              {kevCount > 0 && (
                <Badge variant="critical" className="gap-1">
                  <ShieldAlert className="h-3 w-3" />
                  {kevCount} KEV
                </Badge>
              )}
              {report.vendor && <Badge variant="muted">{report.vendor}</Badge>}
            </div>
            <p className="mt-1 line-clamp-1 text-xs text-muted">{report.executiveSummary}</p>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1 text-xs text-muted">
          <span>{report.articleSource}</span>
          <span>{timeAgo(report.generatedAt)}</span>
        </div>
      </button>

      {expanded && (
        <div className="space-y-4 border-t border-white/[0.06] px-3 pb-4 pt-3 text-sm">
          <div className="flex flex-wrap gap-2">
            <ScoreGauge label="AI Risk Score" score={report.aiRiskScore} icon={<Gauge className={cn("h-4 w-4", riskVariant(report.aiRiskScore) === "critical" ? "text-critical" : riskVariant(report.aiRiskScore) === "high" ? "text-high" : "text-muted")} />} />
            <ScoreGauge label="Confidence" score={report.confidenceScore} icon={<BrainCircuit className="h-4 w-4 text-primary" />} />
          </div>

          <div>
            <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Executive Summary</h4>
            <p className="text-foreground">{report.executiveSummary}</p>
          </div>

          {report.businessImpact && (
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Business Impact</h4>
              <p className="text-foreground">{report.businessImpact}</p>
            </div>
          )}

          {report.threatOverview && (
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-muted">Threat Overview</h4>
              <p className="text-foreground">{report.threatOverview}</p>
            </div>
          )}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <FieldList title="Affected Products" items={report.affectedProducts} />
            <FieldList title="Threat Actors" items={report.threatActors} />
            <FieldList title="Malware Family" items={report.malwareFamily} />
            {report.patchInformation && (
              <div>
                <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">Patch Information</h4>
                <p className="text-sm text-foreground">{report.patchInformation}</p>
              </div>
            )}
          </div>

          {report.cves.length > 0 && (
            <div>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">CVEs</h4>
              <div className="flex flex-wrap gap-1.5">
                {report.cves.map((cve) => (
                  <a
                    key={cve.id}
                    href={cve.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] px-2 py-1 font-mono text-xs text-foreground hover:text-primary hover:underline"
                  >
                    {cve.id}
                    <SeverityBadge severity={cve.severity as never} />
                    {cve.knownExploited && <Badge variant="critical">KEV</Badge>}
                  </a>
                ))}
              </div>
            </div>
          )}

          {report.mitreAttack.length > 0 && (
            <div>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">MITRE ATT&CK Mapping</h4>
              <div className="flex flex-wrap gap-1.5">
                {report.mitreAttack.map((t, i) => (
                  <Badge key={i} variant="cyan" className="font-mono">
                    {t.techniqueId ? `${t.techniqueId} · ` : ""}
                    {t.techniqueName}
                    {t.tactic !== "Unknown" ? ` (${t.tactic})` : ""}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {report.iocs.length > 0 && (
            <div>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">IOCs</h4>
              <ul className="space-y-1 font-mono text-xs text-foreground">
                {report.iocs.map((ioc, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-muted">{ioc.type}:</span>
                    <span className="truncate">{ioc.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <FieldList title="Detection Opportunities" items={report.detectionOpportunities} />
          <FieldList title="Threat Hunting Queries" items={report.threatHuntingQueries} />
          <FieldList title="Immediate Recommendations" items={report.immediateRecommendations} />

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
 * Structured SOC intelligence reports generated by a local LLM from major
 * vendor threat-research and CISA advisories (Cisco Talos, Unit 42,
 * CrowdStrike, Microsoft Security, Google Threat Intelligence, Rapid7, CISA,
 * etc. -- see MAJOR_VENDOR_SOURCES in server/connectors/newsFeeds.js). Facts
 * (severity, CVEs, IOCs) are grounded in this app's own verified
 * extraction/enrichment, never trusted to the model's own recall -- only the
 * analytical fields (summary, detection guidance, hunting queries,
 * confidence/risk scoring) are the model's own synthesis. Runs a small batch
 * in the background every ~10 min (see server/aiThreatSummaryJob.js), so
 * this fills in gradually, not all at once.
 */
export function AiSummarization() {
  const { data, isLoading, isError, error } = useAiThreatSummaries();
  const [search, setSearch] = useState("");
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const reports = data?.reports ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return reports;
    return reports.filter(
      (r) =>
        r.articleTitle.toLowerCase().includes(q) ||
        (r.vendor ?? "").toLowerCase().includes(q) ||
        r.cves.some((c) => c.id.toLowerCase().includes(q)) ||
        r.threatActors.some((a) => a.toLowerCase().includes(q)) ||
        r.malwareFamily.some((m) => m.toLowerCase().includes(q)),
    );
  }, [reports, search]);

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
            Vendor advisories and CISA alerts converted into actionable SOC intelligence -- executive summary, detection opportunities, threat hunting queries, and IOCs, not a news recap.
          </p>
        </div>
        <Input placeholder="Search by title, vendor, CVE, actor, or malware…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full sm:w-80" />
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
                ? "No reports generated yet -- summarization runs a few vendor/CISA articles at a time in the background; check back shortly."
                : "No reports match this search."
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
