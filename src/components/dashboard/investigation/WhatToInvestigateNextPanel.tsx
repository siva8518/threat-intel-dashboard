// Standalone "What To Investigate Next" section -- merges the two "here's
// your next step" fields this page produces (ShouldICarePanel's removed
// "Next Action" and the correlation engine's own next-steps list, formerly
// rendered by the now-removed AI Correlation Summary panel) into ONE place
// instead of two differently-labeled boxes making the same kind of
// recommendation. The correlation summary is still fetched (see
// useInvestigationWorkspace.ts) purely to feed nextSteps here -- its other
// fields (whatIsThis/relationshipNarrative/etc.) are no longer displayed
// anywhere.
//
// Split into two explicitly labeled sections per this platform's own
// constraint: it has NO EDR/SIEM/XDR/firewall/DNS/proxy/netflow/VPN or
// other internal telemetry integration, so "what this platform can
// investigate" (external intelligence pivots -- AI-authored, grounded
// server-side) and "what the analyst must check in their own tools"
// (deterministic, never-AI-authored, always-conditional checklist -- see
// server/investigation/actionability.js#environmentalValidationChecklist)
// must never be presented as though this platform already performed both.
import { Sparkles, Compass, ShieldQuestion } from "lucide-react";
import { Section } from "../reportPrimitives";
import type { ShouldICareAssessment, CorrelationSummary } from "@/types/threat-intel";

interface WhatToInvestigateNextPanelProps {
  shouldICare: ShouldICareAssessment | null;
  shouldICarePending: boolean;
  correlationSummary: CorrelationSummary | null;
  correlationSummaryPending: boolean;
  environmentalValidationChecklist: string[];
}

export function WhatToInvestigateNextPanel({ shouldICare, shouldICarePending, correlationSummary, correlationSummaryPending, environmentalValidationChecklist }: WhatToInvestigateNextPanelProps) {
  const nextAction = shouldICare?.nextAction ?? null;
  const nextSteps = correlationSummary?.nextSteps ?? [];
  // Either underlying generation may still be running -- show the content
  // that's already in as soon as it's in, rather than waiting on both, but
  // keep a quiet "still generating" note while a source that hasn't
  // resolved yet might still add more.
  const stillWaiting = (shouldICarePending && !shouldICare) || (correlationSummaryPending && !correlationSummary);
  const hasIntelligenceContent = Boolean(nextAction) || nextSteps.length > 0;

  if (!hasIntelligenceContent && environmentalValidationChecklist.length === 0 && !stillWaiting) return null;

  return (
    <Section title="What To Investigate Next">
      <div className="space-y-5">
        <div>
          <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            <Compass className="h-3.5 w-3.5" /> Section 1 — Intelligence Investigation (this platform)
          </p>
          <div className="space-y-2">
            {nextAction && <p className="text-sm text-foreground">{nextAction}</p>}
            {nextSteps.length > 0 && (
              <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
                {nextSteps.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ul>
            )}
            {!hasIntelligenceContent && !stillWaiting && <p className="text-xs text-muted">No further intelligence pivots identified.</p>}
            {stillWaiting && (
              <p className="flex items-center gap-1.5 text-xs text-muted">
                <Sparkles className="h-3.5 w-3.5 animate-pulse text-primary" /> Still generating additional investigative guidance…
              </p>
            )}
          </div>
        </div>

        {environmentalValidationChecklist.length > 0 && (
          <div>
            <p className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
              <ShieldQuestion className="h-3.5 w-3.5" /> Section 2 — Environmental Validation (your own tools)
            </p>
            <p className="mb-1.5 text-xs text-muted">This platform has no EDR/SIEM/network-telemetry integration -- these steps can only be completed in your own security tools.</p>
            <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
              {environmentalValidationChecklist.map((line, i) => (
                <li key={i}>{line}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Section>
  );
}
