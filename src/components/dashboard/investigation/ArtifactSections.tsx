// Email Address / File Name / Process Name / Registry Key / User Agent
// Indicator-Specific Intelligence -- cross-reference-only, see
// server/investigation/artifactModule.js for why no external lookup exists.
import { Section } from "../reportPrimitives";
import type { InvestigationRelatedIntelligence } from "@/types/threat-intel";

export function ArtifactIntelligenceSection({ note, crossReference }: { note: string; crossReference: InvestigationRelatedIntelligence }) {
  const hasHits = crossReference.matchedMalwareFamilies.length > 0 || crossReference.relatedIocs.length > 0;
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-dashed border-white/15 bg-white/[0.02] p-3 text-xs text-muted">{note}</div>
      {hasHits && (
        <Section title="Found in This Platform's Own Data">
          <ul className="space-y-1 text-xs text-foreground">
            {crossReference.relatedIocs.map((r, i) => (
              <li key={i}>
                Linked to malware family <span className="font-mono font-semibold">{r.malwareFamily}</span>
                {r.firstSeen ? ` (first seen ${new Date(r.firstSeen).toLocaleDateString()})` : ""}
              </li>
            ))}
          </ul>
        </Section>
      )}
      {/* No local "not found" fallback here -- the Search Coverage panel above already reports this honestly alongside every other layer checked. */}
    </div>
  );
}
