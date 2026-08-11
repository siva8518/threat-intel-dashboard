// Sandbox Analysis -- surfaces server/sandboxIntelligence.js's record for
// this search's indicator: whether it's ever been checked/submitted, what
// came back, and (only when appropriate -- see server/sandboxApplicability.js)
// an explicit "Analyze in Sandbox" action. This platform NEVER auto-submits
// an IOC; submission only ever happens from this button, on an explicit
// analyst click.
import { FlaskConical, Loader2, ShieldAlert, ShieldQuestion, Clock3 } from "lucide-react";
import { Section } from "../reportPrimitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useSandboxStatus, useSubmitSandboxAnalysis } from "@/hooks/useSandboxAnalysis";
import type { InvestigationSandboxContext, SandboxReport } from "@/types/threat-intel";

function formatDate(iso: string | null): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "Unknown" : d.toLocaleString();
}

const VERDICT_VARIANT: Record<SandboxReport["verdict"], "critical" | "high" | "low" | "muted"> = {
  malicious: "critical",
  suspicious: "high",
  clean: "low",
  unknown: "muted",
};

function ReportBody({ report }: { report: SandboxReport }) {
  return (
    <div className="space-y-4">
      {report.incomplete && (
        <p className="rounded-lg border border-medium/30 bg-medium/10 p-2.5 text-xs text-medium">
          This report is incomplete -- some behavioral fields were not present in the provider's response. Treat any absence below as "not reported", not "confirmed absent".
        </p>
      )}
      <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-4">
        <div>
          <span className="text-muted">Verdict: </span>
          <Badge variant={VERDICT_VARIANT[report.verdict]}>{report.verdictLabel ?? report.verdict}</Badge>
        </div>
        <div>
          <span className="text-muted">Threat Score: </span>
          <span className="font-semibold text-foreground">{report.threatScore ?? "Not Reported"}</span>
        </div>
        <div>
          <span className="text-muted">Analyzed: </span>
          <span className="font-semibold text-foreground">{formatDate(report.analyzedAt)}</span>
        </div>
        <div>
          <span className="text-muted">Environment: </span>
          <span className="font-semibold text-foreground">{report.environment ?? "Not Reported"}</span>
        </div>
        <div>
          <span className="text-muted">Execution Observed: </span>
          <span className="font-semibold text-foreground">{report.executionObserved ? "Yes" : "No"}</span>
        </div>
        {report.malwareFamily && (
          <div>
            <span className="text-muted">Malware Family: </span>
            <span className="font-semibold text-foreground">{report.malwareFamily}</span>
          </div>
        )}
      </div>

      {report.processes.length > 0 && (
        <Section title={`Processes Spawned (${report.processes.length})`}>
          <ul className="space-y-1 text-xs text-foreground/90">
            {report.processes.slice(0, 10).map((p, i) => (
              <li key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2">
                <span className="font-semibold">{p.name ?? "Unnamed process"}</span>
                {p.commandLine && <span className="block text-muted">{p.commandLine}</span>}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {report.networkConnections.length > 0 && (
        <Section title={`Network Activity (${report.networkConnections.length})`}>
          <ul className="flex flex-wrap gap-1.5">
            {report.networkConnections.slice(0, 15).map((c, i) => (
              <li key={i} className="rounded-md border border-white/[0.06] bg-white/[0.02] px-2 py-1 text-xs text-foreground/90">
                {c.ip}
                {c.port ? `:${c.port}` : ""}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {report.dnsQueries.length > 0 && (
        <Section title={`DNS Queries (${report.dnsQueries.length})`}>
          <ul className="flex flex-wrap gap-1.5">
            {report.dnsQueries.slice(0, 15).map((d, i) => (
              <li key={i} className="rounded-md border border-white/[0.06] bg-white/[0.02] px-2 py-1 text-xs text-foreground/90">
                {d.domain}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {report.filesDropped.length > 0 && (
        <Section title={`Files Dropped (${report.filesDropped.length})`}>
          <ul className="space-y-1 text-xs text-foreground/90">
            {report.filesDropped.slice(0, 10).map((f, i) => (
              <li key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2">
                <span className="font-semibold">{f.name ?? "Unnamed file"}</span>
                {f.sha256 && <span className="block break-all text-muted">{f.sha256}</span>}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {report.persistenceIndicators.length > 0 && (
        <Section title="Persistence">
          <ul className="list-disc space-y-1 pl-4 text-xs text-foreground/90">
            {report.persistenceIndicators.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </Section>
      )}

      {report.mitreAttackTechniques.length > 0 && (
        <Section title="MITRE ATT&CK Techniques">
          <ul className="flex flex-wrap gap-1.5">
            {report.mitreAttackTechniques.map((m, i) => (
              <li key={i} className="rounded-md border border-white/[0.06] bg-white/[0.02] px-2 py-1 text-xs text-foreground/90">
                {m.id}
                {m.name ? ` -- ${m.name}` : ""}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {(report.additionalIocs.ips.length > 0 || report.additionalIocs.domains.length > 0 || report.additionalIocs.urls.length > 0 || report.additionalIocs.hashes.length > 0) && (
        <Section title="Additional Indicators">
          <p className="text-xs text-foreground/90">
            {report.additionalIocs.ips.length} IP(s), {report.additionalIocs.domains.length} domain(s), {report.additionalIocs.urls.length} URL(s), {report.additionalIocs.hashes.length} hash(es) -- see the Relationships graph for these as pivotable nodes.
          </p>
        </Section>
      )}

      {report.reportUrl && (
        <a href={report.reportUrl} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline">
          View full report on {report.provider} →
        </a>
      )}
    </div>
  );
}

export function SandboxAnalysisPanel({ sandbox }: { sandbox: InvestigationSandboxContext | null }) {
  const submitM = useSubmitSandboxAnalysis();
  const type = sandbox?.record.indicatorType ?? null;
  const value = sandbox?.record.indicatorValue ?? null;
  const statusQ = useSandboxStatus(type, value, sandbox?.record ?? null);

  if (!sandbox) return null;
  const record = statusQ.data ?? sandbox.record;
  const { applicability } = sandbox;

  const canSubmit = applicability.recommendedAction === "submit" && (record.status === "not_analyzed" || record.status === "failed");

  return (
    <Section title="Sandbox Analysis">
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-1.5">
            <FlaskConical className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold text-foreground">
              {record.provider ?? "Hybrid Analysis"} Sandbox{record.status !== "not_analyzed" ? " -- " : ""}
              {record.status === "existing_available" && "Existing Analysis Available"}
              {record.status === "completed" && "Analysis Completed"}
              {(record.status === "submitted" || record.status === "in_progress") && "Analysis In Progress"}
              {record.status === "failed" && "Analysis Failed"}
              {record.status === "rate_limited" && "Submission Rate Limited"}
              {(record.status === "not_analyzed" || record.status === "unavailable") && "Not Analyzed"}
            </span>
          </div>
          {canSubmit && (
            <Button size="sm" variant="outline" disabled={submitM.isPending} onClick={() => type && value && submitM.mutate({ type, value })}>
              {submitM.isPending ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="mr-1.5 h-3.5 w-3.5" />}
              Analyze in Sandbox
            </Button>
          )}
        </div>

        {(record.status === "submitted" || record.status === "in_progress") && (
          <p className="flex items-center gap-1.5 text-xs text-muted">
            <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" /> Submitted {formatDate(record.submittedAt)} -- checking for results automatically.
          </p>
        )}

        {record.status === "failed" && (
          <p className="flex items-center gap-1.5 text-xs text-critical">
            <ShieldAlert className="h-3.5 w-3.5" /> {record.error ?? "Sandbox analysis failed."}
          </p>
        )}

        {record.status === "rate_limited" && (
          <p className="flex items-center gap-1.5 text-xs text-medium">
            <Clock3 className="h-3.5 w-3.5" /> {record.error ?? "Sandbox submission is rate limited -- try again shortly."}
          </p>
        )}

        {(record.status === "not_analyzed" || record.status === "unavailable") && (
          <p className="flex items-center gap-1.5 text-xs text-muted">
            <ShieldQuestion className="h-3.5 w-3.5" /> {applicability.reason}
          </p>
        )}

        {(record.status === "existing_available" || record.status === "completed") && record.report && (
          <div className="mt-2">
            <ReportBody report={record.report} />
          </div>
        )}
      </div>
      {submitM.isError && <p className="mt-2 text-xs text-critical">{(submitM.error as Error).message}</p>}
    </Section>
  );
}
