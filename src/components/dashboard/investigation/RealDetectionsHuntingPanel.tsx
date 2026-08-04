// Real (non-LLM) detection-rule citations + hunting-query previews, sourced
// from server/investigation/investigationGraph.js's node.metadata --
// distinct from AiReportSection.tsx's DetectionOpportunitiesPanel, which is
// LLM-generated and only populated after the optional "Generate AI Report"
// click. This panel answers "what should Detection Engineering deploy /
// what hunting opportunities exist" the instant the search resolves.
import { ExternalLink } from "lucide-react";
import { Section } from "../reportPrimitives";
import type { GraphNode } from "@/types/threat-intel";

interface DetectionRuleMeta {
  label: string;
  path: string;
  url: string;
}

interface HuntingQueryMeta {
  platform: string;
  query: string;
  source: string;
  sourceUrl: string;
}

export function RealDetectionsHuntingPanel({ graphNode }: { graphNode: GraphNode | null }) {
  const meta = (graphNode?.metadata ?? {}) as { detectionRules?: DetectionRuleMeta[]; huntingQueries?: HuntingQueryMeta[] };
  const detectionRules = meta.detectionRules ?? [];
  const huntingQueries = meta.huntingQueries ?? [];

  return (
    <Section title="Detections &amp; Hunting">
      <div className="space-y-3 text-xs">
        <div>
          <p className="mb-1 font-semibold text-foreground">Detection Rules</p>
          {detectionRules.length === 0 ? (
            <p className="text-muted">No existing public Sigma/YARA rule found for this indicator or its associated malware family yet.</p>
          ) : (
            <ul className="space-y-1">
              {detectionRules.map((r) => (
                <li key={`${r.label}:${r.path}`}>
                  <a href={r.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                    {r.label}: {r.path}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <p className="mb-1 font-semibold text-foreground">Hunting Opportunities</p>
          {huntingQueries.length === 0 ? (
            <p className="text-muted">No prebuilt hunting query available yet for this indicator or its associated malware family.</p>
          ) : (
            <ul className="space-y-1.5">
              {huntingQueries.map((q, i) => (
                <li key={i}>
                  <span className="font-semibold text-foreground">{q.platform}</span> — <span className="text-muted">{q.source}</span>
                  <pre className="mt-1 max-h-24 overflow-y-auto whitespace-pre-wrap rounded-lg border border-white/10 bg-black/20 p-2 font-mono text-[11px] text-foreground/90">{q.query}</pre>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Section>
  );
}
