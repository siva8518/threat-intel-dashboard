// Standalone "What To Investigate Next" section -- merges the two "here's
// your next step" fields this page produces (ShouldICarePanel's removed
// "Next Action" and the correlation engine's own next-steps list, formerly
// rendered by the now-removed AI Correlation Summary panel) into ONE place
// instead of two differently-labeled boxes making the same kind of
// recommendation. The correlation summary is still fetched (see
// useInvestigationWorkspace.ts) purely to feed nextSteps here -- its other
// fields (whatIsThis/relationshipNarrative/etc.) are no longer displayed
// anywhere.
import { Sparkles } from "lucide-react";
import { Section } from "../reportPrimitives";
import type { ShouldICareAssessment, CorrelationSummary } from "@/types/threat-intel";

interface WhatToInvestigateNextPanelProps {
  shouldICare: ShouldICareAssessment | null;
  shouldICarePending: boolean;
  correlationSummary: CorrelationSummary | null;
  correlationSummaryPending: boolean;
}

export function WhatToInvestigateNextPanel({ shouldICare, shouldICarePending, correlationSummary, correlationSummaryPending }: WhatToInvestigateNextPanelProps) {
  const nextAction = shouldICare?.nextAction ?? null;
  const nextSteps = correlationSummary?.nextSteps ?? [];
  // Either underlying generation may still be running -- show the content
  // that's already in as soon as it's in, rather than waiting on both, but
  // keep a quiet "still generating" note while a source that hasn't
  // resolved yet might still add more.
  const stillWaiting = (shouldICarePending && !shouldICare) || (correlationSummaryPending && !correlationSummary);

  if (!nextAction && nextSteps.length === 0 && !stillWaiting) return null;

  return (
    <Section title="What To Investigate Next">
      <div className="space-y-3">
        {nextAction && <p className="text-sm text-foreground">{nextAction}</p>}
        {nextSteps.length > 0 && (
          <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
            {nextSteps.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        )}
        {stillWaiting && (
          <p className="flex items-center gap-1.5 text-xs text-muted">
            <Sparkles className="h-3.5 w-3.5 animate-pulse text-primary" /> Still generating additional investigative guidance…
          </p>
        )}
      </div>
    </Section>
  );
}
