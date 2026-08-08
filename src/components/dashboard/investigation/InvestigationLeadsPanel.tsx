// "Continue Investigation" checklist -- groups a node's own edges by target
// type into a scannable count summary ("3 Related Campaigns"), so an
// analyst is never left concluding "no relationships found" when other real
// pivots exist. Sits alongside (not replacing) the unavailableRelationships
// list rendered next to it, which explains genuine data-source gaps.
import { useState } from "react";
import { CheckCircle2, ChevronDown, ChevronRight } from "lucide-react";
import type { GraphNodeType } from "@/types/threat-intel";
import type { GraphEdgeWithSource } from "@/hooks/useInvestigationGraph";

const PLURAL_LABEL: Record<GraphNodeType, string> = {
  actor: "Related Threat Actors",
  campaign: "Related Campaigns",
  malware: "Related Malware Families",
  cve: "Related CVEs",
  victim: "Related Victims / Organizations",
  ip: "Related IP Addresses",
  domain: "Related Domains",
  url: "Related URLs",
  hash: "Related File Hashes",
  email: "Related Email Addresses",
  fileName: "Related File Names",
  processName: "Related Process Names",
  registryKey: "Related Registry Keys",
  userAgent: "Related User Agents",
  attackTechnique: "Related ATT&CK Techniques",
  country: "Related Countries",
  report: "Related AI Summarization Reports",
  asn: "Related ASNs",
  industry: "Targeted Industries",
};

function LeadGroup({ type, edges, onSelect }: { type: GraphNodeType; edges: GraphEdgeWithSource[]; onSelect: (type: GraphNodeType, key: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-low/20 bg-low/5">
      <button type="button" onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-1.5 px-2.5 py-1.5 text-left text-[11px] font-semibold text-low">
        <CheckCircle2 className="h-3 w-3 shrink-0" />
        <span className="flex-1">
          {edges.length} {PLURAL_LABEL[type]}
        </span>
        {open ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />}
      </button>
      {open && (
        <div className="space-y-0.5 px-2 pb-2">
          {edges.slice(0, 10).map((e) => (
            <button
              key={`${e.targetType}:${e.targetKey}`}
              type="button"
              onClick={() => onSelect(e.targetType, e.targetKey)}
              className="block w-full truncate rounded px-1.5 py-1 text-left font-mono text-[11px] text-foreground hover:bg-white/[0.06]"
            >
              {e.targetLabel}
            </button>
          ))}
          {edges.length > 10 && <p className="px-1.5 py-0.5 text-[10px] text-muted">+{edges.length - 10} more</p>}
        </div>
      )}
    </div>
  );
}

export function InvestigationLeadsPanel({ edges, onSelect }: { edges: GraphEdgeWithSource[]; onSelect: (type: GraphNodeType, key: string) => void }) {
  if (edges.length === 0) return null;

  const groups = new Map<GraphNodeType, GraphEdgeWithSource[]>();
  for (const e of edges) {
    if (!groups.has(e.targetType)) groups.set(e.targetType, []);
    groups.get(e.targetType)!.push(e);
  }
  const sortedTypes = Array.from(groups.keys()).sort((a, b) => groups.get(b)!.length - groups.get(a)!.length);

  return (
    <div>
      <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Continue Investigation</p>
      <div className="space-y-1.5">
        {sortedTypes.map((type) => (
          <LeadGroup key={type} type={type} edges={groups.get(type)!} onSelect={onSelect} />
        ))}
      </div>
    </div>
  );
}
