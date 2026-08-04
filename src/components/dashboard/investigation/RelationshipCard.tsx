// Shared relationship-edge card -- "why this exists, confidence, first/last
// seen, supporting reports, sources" -- used by both the full Investigation
// Graph canvas (InvestigationGraph.tsx) and the Investigation Workspace's
// compact Relationships section, so there's exactly one rendering of an
// edge's evidence anywhere in the app.
import { Badge } from "@/components/ui/badge";
import type { GraphConfidence } from "@/types/threat-intel";
import type { GraphEdgeWithSource } from "@/hooks/useInvestigationGraph";

const CONFIDENCE_BADGE: Record<GraphConfidence, "high" | "medium" | "low"> = { High: "high", Medium: "medium", Low: "low" };

export function RelationshipCard({ edge, onFocus }: { edge: GraphEdgeWithSource; onFocus: () => void }) {
  return (
    <button type="button" onClick={onFocus} className="block w-full rounded-lg border border-white/10 bg-white/[0.03] p-2.5 text-left text-xs hover:border-primary/40">
      <div className="flex items-center justify-between gap-2">
        <span className="font-semibold text-foreground">
          {edge.relationship} <span className="font-mono text-primary">{edge.targetLabel}</span>
        </span>
        <Badge variant={CONFIDENCE_BADGE[edge.confidence]}>{edge.confidence}</Badge>
      </div>
      <p className="mt-1 text-muted" title={edge.why}>
        {edge.why}
      </p>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted">
        {edge.firstSeen && <span>First seen {edge.firstSeen.slice(0, 10)}</span>}
        {edge.lastSeen && edge.lastSeen !== edge.firstSeen && <span>Last seen {edge.lastSeen.slice(0, 10)}</span>}
        <span>{edge.supportingReportCount === null ? "Supporting reports: not tracked" : `${edge.supportingReportCount} supporting report(s)`}</span>
        <span>{edge.sources.join(", ")}</span>
      </div>
    </button>
  );
}
