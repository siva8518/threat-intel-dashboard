// Renders server/investigation/graphInsights.js's synthesized analysis --
// explicitly NOT a restatement of the Relationships section above it (see
// that file's SYSTEM_PROMPT). Fired automatically by useInvestigationWorkspace
// once relationships finish loading, so this renders progressively: the
// rest of the Workspace (verdict/why-care/relationships/detections/
// recommended actions) is already fully usable while this one panel is
// still generating -- never blocks the page.
import { Sparkles, Target, Users } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";
import { ErrorState } from "../ErrorState";
import type { GraphInsights } from "@/types/threat-intel";

interface AiGraphInsightsPanelProps {
  insights: GraphInsights | null;
  pending: boolean;
  error: string | null;
  onFocusEntity: (entity: string) => void;
  /** Defaults to the automatic single-node summary's title -- pass a distinct title (e.g. "Full Graph Analysis") for a manually-triggered instance scoped to a larger, multi-hop edge set, so the two are never visually confused. */
  title?: string;
}

export function AiGraphInsightsPanel({ insights, pending, error, onFocusEntity, title = "AI Investigation Summary" }: AiGraphInsightsPanelProps) {
  if (pending) {
    return (
      <Section title={title}>
        <p className="mb-2 flex items-center gap-1.5 text-xs text-muted">
          <Sparkles className="h-3.5 w-3.5 animate-pulse text-primary" />
          Generating AI investigation summary — analyzing the relationships above, this can take up to a minute…
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
      <Section title={title}>
        <ErrorState message={error} />
      </Section>
    );
  }

  if (!insights) return null;

  return (
    <Section title={title}>
      <div className="space-y-4">
        <p className="text-sm text-foreground">{insights.summary}</p>

        {(insights.likelyAttackChain || insights.strongestActorMatch) && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {insights.likelyAttackChain && (
              <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                  <Target className="h-3.5 w-3.5" /> Likely Attack Chain
                </p>
                <p className="text-xs text-foreground">{insights.likelyAttackChain}</p>
              </div>
            )}
            {insights.strongestActorMatch && (
              <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                  <Users className="h-3.5 w-3.5" /> Strongest Actor Match
                </p>
                <button type="button" onClick={() => onFocusEntity(insights.strongestActorMatch!.name)} className="font-mono text-xs font-semibold text-primary hover:underline">
                  {insights.strongestActorMatch.name} →
                </button>
                <p className="mt-0.5 text-xs text-muted">{insights.strongestActorMatch.reasoning}</p>
              </div>
            )}
          </div>
        )}

        {insights.priorityInvestigationTargets.length > 0 && (
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Priority Investigation Targets</p>
            <div className="space-y-1.5">
              {insights.priorityInvestigationTargets.map((t) => (
                <button
                  key={`${t.entityType}:${t.entity}`}
                  type="button"
                  onClick={() => onFocusEntity(t.entity)}
                  className="block w-full rounded-lg border border-white/10 bg-white/[0.03] p-2 text-left text-xs hover:border-primary/40"
                >
                  <span className="font-mono font-semibold text-primary">{t.entity}</span> <span className="text-muted">({t.entityType})</span>
                  <p className="mt-0.5 text-muted">{t.reasoning}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {insights.crossReportPatterns.length > 0 && (
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Cross-Report Patterns</p>
            <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
              {insights.crossReportPatterns.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="flex items-center gap-1.5">
          <Badge variant="muted">AI-generated — {insights.model}</Badge>
        </div>
      </div>
    </Section>
  );
}
