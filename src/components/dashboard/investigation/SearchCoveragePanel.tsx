// Replaces the old scattered per-type "no results" states (EntitySections.tsx,
// ArtifactSections.tsx, the CVE EmptyState in InvestigationWorkspace.tsx)
// with one honest summary of every intelligence layer this search actually
// consulted -- see server/investigation/coverage.js. A search should almost
// never show "Nothing Found" (only when every layer below genuinely came up
// empty); this panel is what makes that visible instead of five independent
// "no match" messages that never tell the analyst what else was checked.
import { CheckCircle2, CircleDashed, SearchX } from "lucide-react";
import { Section } from "../reportPrimitives";
import type { SearchCoverage } from "@/types/threat-intel";

export function SearchCoveragePanel({ coverage }: { coverage: SearchCoverage }) {
  if (coverage.layers.length === 0) return null;

  return (
    <Section title="Search Coverage">
      {coverage.nothingFound ? (
        <div className="mb-3 flex items-center gap-2 rounded-lg border border-dashed border-white/15 bg-white/[0.02] p-3 text-sm text-muted">
          <SearchX className="h-4 w-4 shrink-0" />
          Every intelligence layer below was checked -- none has evidence for this indicator yet.
        </div>
      ) : (
        <p className="mb-3 text-xs text-muted">Every layer this platform can check for this indicator type, and what each one found.</p>
      )}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {coverage.layers.map((layer) => (
          <div key={layer.name} className="flex items-start gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5 text-xs">
            {layer.hitCount > 0 ? (
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-low" />
            ) : (
              <CircleDashed className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted" />
            )}
            <div className="min-w-0">
              <p className="font-semibold text-foreground">{layer.name}</p>
              <p className="mt-0.5 text-muted">{layer.summary}</p>
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
}
