// Renders server/investigation/correlationSummary.js's synthesis -- reasons
// across the FULL unified investigation result (graph edges, cross-
// referenced entities, ranked findings, real industry data), not just the
// searched entity's own direct graph edges the way AiGraphInsightsPanel
// does. The narrative fields are model-authored; every list below
// (industries/reused infrastructure/ATT&CK techniques/victims/actors/
// campaigns/malware) is real, deterministically-tallied data, never
// model-authored -- see correlationSummary.js's own header comment.
import { AlertOctagon, Building2, Crosshair, Globe2, Sparkles, Target } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";
import { ErrorState } from "../ErrorState";
import type { CorrelationSummary } from "@/types/threat-intel";

interface CorrelationSummaryPanelProps {
  summary: CorrelationSummary | null;
  pending: boolean;
  error: string | null;
  onFocusEntity: (entity: string) => void;
}

export function CorrelationSummaryPanel({ summary, pending, error, onFocusEntity }: CorrelationSummaryPanelProps) {
  if (pending) {
    return (
      <Section title="AI Correlation Summary">
        <p className="mb-2 flex items-center gap-1.5 text-xs text-muted">
          <Sparkles className="h-3.5 w-3.5 animate-pulse text-primary" />
          Correlating across every intelligence layer this platform checked for this entity…
        </p>
        <div className="space-y-2">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
          <Skeleton className="h-16 w-full" />
        </div>
      </Section>
    );
  }

  if (error) {
    return (
      <Section title="AI Correlation Summary">
        <ErrorState message={error} />
      </Section>
    );
  }

  if (!summary) return null;

  const entityList = (label: string, icon: React.ReactNode, items: string[]) =>
    items.length > 0 && (
      <div>
        <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
          {icon} {label}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {items.map((item) => (
            <button key={item} type="button" onClick={() => onFocusEntity(item)} className="rounded-lg border border-white/10 bg-white/[0.03] px-2 py-1 text-xs font-mono font-semibold text-primary hover:border-primary/40">
              {item}
            </button>
          ))}
        </div>
      </div>
    );

  return (
    <Section title="AI Correlation Summary">
      <div className="space-y-4">
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">What Is This?</p>
          <p className="text-sm text-foreground">{summary.whatIsThis}</p>
        </div>
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Why It Matters</p>
          <p className="text-sm text-foreground">{summary.whyItMatters}</p>
        </div>
        <div>
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">How It's Related</p>
          <p className="text-sm text-foreground">{summary.relationshipNarrative}</p>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {entityList("Related Threat Actors", <Target className="h-3.5 w-3.5" />, summary.relatedActors)}
          {entityList("Overlapping Campaigns", <Crosshair className="h-3.5 w-3.5" />, summary.relatedCampaigns)}
          {entityList("Overlapping Malware", <AlertOctagon className="h-3.5 w-3.5" />, summary.relatedMalware)}
          {entityList("Victims Targeted", <Building2 className="h-3.5 w-3.5" />, summary.victimsTargeted)}
        </div>

        {summary.industriesAffected.length > 0 && (
          <div>
            <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              <Globe2 className="h-3.5 w-3.5" /> Industries Affected
            </p>
            <div className="flex flex-wrap gap-1.5">
              {summary.industriesAffected.map((row) => (
                <Badge key={row.industry} variant={row.relevance === "Critical" || row.relevance === "High" ? "critical" : "muted"}>
                  {row.industry} — {row.relevance}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {summary.attackTechniques.length > 0 && (
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">ATT&amp;CK Techniques</p>
            <div className="flex flex-wrap gap-1.5">
              {summary.attackTechniques.map((t) => (
                <Badge key={t.id} variant="muted" className="font-mono">
                  {t.id} {t.name}
                </Badge>
              ))}
            </div>
          </div>
        )}

        <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
          <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Infrastructure Reuse</p>
          <p className="text-xs text-foreground">{summary.infrastructureReuseAssessment}</p>
          {summary.reusedInfrastructure.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {summary.reusedInfrastructure.map((item) => (
                <span key={`${item.indicatorType}:${item.indicator}`} className="rounded-lg border border-white/10 bg-black/20 px-2 py-0.5 font-mono text-[11px] text-foreground/90">
                  {item.indicator}
                </span>
              ))}
            </div>
          )}
        </div>

        {summary.nextSteps.length > 0 && (
          <div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-3">
            <p className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-primary">
              <Sparkles className="h-3.5 w-3.5" /> What To Investigate Next
            </p>
            <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
              {summary.nextSteps.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
          </div>
        )}

        <Badge variant="muted">AI-generated — {summary.model}</Badge>
      </div>
    </Section>
  );
}
