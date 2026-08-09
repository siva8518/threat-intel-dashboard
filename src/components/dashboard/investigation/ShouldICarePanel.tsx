// Renders server/investigation/shouldICare.js's synthesis layer -- the
// section that sits ABOVE EvidencePanel.tsx's per-source card grid and never
// restates it. Three explicit blocks: a deterministic OVERALL ASSESSMENT
// (Risk/Confidence/Analyst Decision/Reason -- straight from the verdict
// engine, never model-authored), COMBINED INTELLIGENCE ASSESSMENT (what the
// evidence indicates once compared -- conflicts, independence, shared
// infrastructure), and LIKELY MALICIOUS INTENT (only ever populated when
// real evidence supports a specific intent -- fail-closed enforced
// server-side), plus ENVIRONMENTAL RELEVANCE. `assessment.nextAction` is
// deliberately NOT rendered here -- it's folded into the standalone "What To
// Investigate Next" section instead (see WhatToInvestigateNextPanel.tsx),
// so a next-step recommendation lives in exactly one place on the page.
// `analystDecision` is deterministic pass-through; the prose fields are the
// model's narrative synthesis, grounded and validated server-side before
// this component ever sees them.
import { Sparkles, ShieldAlert, Layers, Target, Building2 } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";
import type { ShouldICareAssessment, InvestigationResult, AnalystDecision, Severity } from "@/types/threat-intel";

const DECISION_BADGE: Record<AnalystDecision, "critical" | "high" | "medium" | "low" | "muted" | "cyan"> = {
  Block: "critical",
  "Investigate Immediately": "high",
  "Investigate If Observed Internally": "medium",
  Monitor: "cyan",
  Watchlist: "muted",
  "Do Not Block": "low",
  "No Action Required": "muted",
};

const SEVERITY_BADGE: Record<Severity, "critical" | "high" | "medium" | "low" | "muted"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "muted",
};

interface ShouldICarePanelProps {
  assessment: ShouldICareAssessment | null;
  pending: boolean;
  error: string | null;
  overview: InvestigationResult["overview"];
}

function OverallAssessment({ overview }: { overview: InvestigationResult["overview"] }) {
  const verdict = overview.verdict;
  return (
    <div className="grid grid-cols-2 gap-2 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 sm:grid-cols-4">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Risk</p>
        <Badge variant={SEVERITY_BADGE[verdict.severity]}>{verdict.severity}</Badge>
      </div>
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Confidence</p>
        <p className="text-sm font-semibold text-foreground">{verdict.confidence}</p>
      </div>
      <div className="col-span-2 sm:col-span-2">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Analyst Decision</p>
        <Badge variant={DECISION_BADGE[verdict.analystDecision]}>{verdict.analystDecision.toUpperCase()}</Badge>
      </div>
      <div className="col-span-2 sm:col-span-4">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Reason</p>
        <p className="text-xs text-foreground">{verdict.analystDecisionReasoning}</p>
      </div>
    </div>
  );
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
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
        </div>
      </Section>
    );
  }

  // No AI assessment available (error, or skipped because there was
  // genuinely no evidence to reason over -- see coverage.nothingFound in
  // useInvestigationWorkspace.ts) -- fall back to the deterministic Overall
  // Assessment block directly rather than showing a bare error box.
  if (!assessment) {
    return (
      <Section title="Should I Care?">
        <div className="space-y-2">
          <OverallAssessment overview={overview} />
          {error && <p className="text-xs text-muted">(AI narrative unavailable: {error} -- showing the underlying verdict directly.)</p>}
        </div>
      </Section>
    );
  }

  return (
    <Section title="Should I Care?">
      <div className="space-y-4">
        <OverallAssessment overview={overview} />

        <div>
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Layers className="h-3.5 w-3.5" /> Combined Intelligence Assessment
          </p>
          <p className="text-sm text-foreground">{assessment.combinedAssessment}</p>
        </div>

        <div>
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Target className="h-3.5 w-3.5" /> Likely Malicious Intent
          </p>
          <p className="text-sm text-foreground">{assessment.likelyMaliciousIntent}</p>
        </div>

        <div>
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Building2 className="h-3.5 w-3.5" /> Environmental Relevance
          </p>
          <div className="space-y-1.5 rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
            <Badge variant="muted">{assessment.environmentalRelevance.label}</Badge>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Reason</p>
              <p className="text-xs text-foreground">{assessment.environmentalRelevance.reason}</p>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted">Recommended Analyst Action</p>
              <p className="text-xs text-foreground">{assessment.environmentalRelevance.recommendedAction}</p>
            </div>
          </div>
        </div>

        <Badge variant="muted">
          <ShieldAlert className="h-3 w-3" /> AI-generated — {assessment.model}
        </Badge>
      </div>
    </Section>
  );
}
