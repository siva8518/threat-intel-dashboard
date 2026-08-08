// Renders server/investigation/shouldICare.js's human-centric assessment --
// replaces the old source-first "VirusTotal reports malicious..." sentence
// with three explicitly-labeled layers an analyst actually asks about:
// EXTERNAL INTELLIGENCE (what's been reported out in the world, synthesized
// -- never source-name-first), ORGANIZATIONAL RISK (whether it's known to
// have touched THIS environment -- always an honest "cannot be determined"
// until this platform has real telemetry), and ANALYST ACTION (a concrete
// next step). `evidenceBullets`/`analystDecision`/`infrastructureNote` are
// deterministic, never model-authored -- only the narrative prose is.
import { Sparkles, ShieldAlert, Building2, Compass } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";
import type { ShouldICareAssessment, InvestigationResult, AnalystDecision } from "@/types/threat-intel";

const DECISION_BADGE: Record<AnalystDecision, "critical" | "high" | "medium" | "low" | "muted" | "cyan"> = {
  Block: "critical",
  "Investigate Immediately": "high",
  "Investigate If Observed Internally": "medium",
  Monitor: "cyan",
  Watchlist: "muted",
  "Do Not Block": "low",
  "No Action Required": "muted",
};

interface ShouldICarePanelProps {
  assessment: ShouldICareAssessment | null;
  pending: boolean;
  error: string | null;
  overview: InvestigationResult["overview"];
}

export function ShouldICarePanel({ assessment, pending, error, overview }: ShouldICarePanelProps) {
  if (pending) {
    return (
      <Section title="Should I Care?">
        <p className="mb-2 flex items-center gap-1.5 text-xs text-muted">
          <Sparkles className="h-3.5 w-3.5 animate-pulse text-primary" />
          Weighing the evidence and building an analyst assessment…
        </p>
        <div className="space-y-2">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
        </div>
      </Section>
    );
  }

  // No AI assessment available (error, or skipped because there was
  // genuinely no evidence to reason over -- see coverage.nothingFound in
  // useInvestigationWorkspace.ts) -- fall back to the deterministic verdict
  // fields directly rather than showing a bare error box or nothing at all.
  if (!assessment) {
    const verdict = overview.verdict;
    return (
      <Section title="Should I Care?">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={DECISION_BADGE[verdict.analystDecision]}>{verdict.analystDecision.toUpperCase()}</Badge>
            <span className="text-sm font-semibold text-foreground">{verdict.label}</span>
          </div>
          <p className="text-sm text-foreground">{verdict.reasoning}</p>
          {error && <p className="text-xs text-muted">(AI narrative unavailable: {error} -- showing the underlying verdict directly.)</p>}
        </div>
      </Section>
    );
  }

  return (
    <Section title="Should I Care?">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={DECISION_BADGE[assessment.analystDecision]}>{assessment.analystDecision.toUpperCase()}</Badge>
          <span className="text-sm font-semibold text-foreground">{assessment.headline}</span>
        </div>

        <div>
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <ShieldAlert className="h-3.5 w-3.5" /> External Intelligence
          </p>
          <p className="text-sm text-foreground">{assessment.externalIntelligence}</p>
          {assessment.evidenceBullets.length > 0 && (
            <ul className="mt-2 space-y-1 pl-4 text-xs text-muted">
              {assessment.evidenceBullets.map((line, i) => (
                <li key={i} className="list-disc">
                  {line}
                </li>
              ))}
            </ul>
          )}
          {assessment.infrastructureNote && <p className="mt-2 rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-xs text-muted">{assessment.infrastructureNote}</p>}
        </div>

        <div>
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Building2 className="h-3.5 w-3.5" /> Organizational Risk
          </p>
          <p className="text-sm text-foreground">{assessment.organizationalRisk}</p>
        </div>

        <div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-3">
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-primary">
            <Compass className="h-3.5 w-3.5" /> Analyst Action
          </p>
          <p className="text-sm text-foreground">{assessment.analystAction}</p>
        </div>

        <Badge variant="muted">AI-generated — {assessment.model}</Badge>
      </div>
    </Section>
  );
}
