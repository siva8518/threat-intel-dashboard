import { useEffect, useState } from "react";
import { Waypoints, ArrowRight, Search } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { Section, Breadcrumb } from "./reportPrimitives";
import { usePivotChain } from "@/hooks/usePivotChain";
import type { PivotNodeType, PivotEdge } from "@/types/threat-intel";

const NODE_TYPE_LABEL: Record<PivotNodeType, string> = {
  actor: "Threat Actor",
  campaign: "Campaign",
  malware: "Malware Family",
  cve: "CVE",
  victim: "Victim",
  ip: "IP Address",
  domain: "Domain",
  report: "AI Summarization Report",
};

const PIVOT_ORDER: PivotNodeType[] = ["actor", "campaign", "malware", "cve", "victim", "ip", "domain", "report"];

interface PivotStep {
  type: PivotNodeType;
  key: string;
}

interface PivotChainExplorerProps {
  initialType?: PivotNodeType | null;
  initialKey?: string | null;
}

function NeighborGroup({ type, edges, unavailableReason, onPivot }: { type: PivotNodeType; edges: PivotEdge[]; unavailableReason?: string; onPivot: (type: PivotNodeType, key: string) => void }) {
  return (
    <Section title={NODE_TYPE_LABEL[type]}>
      {unavailableReason ? (
        <p className="text-xs italic text-muted">{unavailableReason}</p>
      ) : edges.length === 0 ? (
        <p className="text-xs text-muted">None found for this entity.</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          {edges.map((edge) => (
            <button
              key={edge.id}
              type="button"
              title={edge.linkBasis}
              onClick={() => onPivot(type, edge.id)}
              className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-xs text-primary hover:border-primary/50"
            >
              {edge.label} <ArrowRight className="inline h-3 w-3" />
            </button>
          ))}
        </div>
      )}
    </Section>
  );
}

/**
 * Lets an analyst walk Threat Actor -> Campaign -> Malware -> CVE -> Victim
 * -> IP -> Domain -> Report one hop at a time, starting from any node --
 * see server/investigation/pivotChain.js. Every edge shown is backed by a
 * real field this app already computes; a hop with no supporting data
 * anywhere in this app renders an explicit reason instead of a silently
 * empty section, same "never fabricate" convention as the rest of this app.
 */
export function PivotChainExplorer({ initialType, initialKey }: PivotChainExplorerProps = {}) {
  const [path, setPath] = useState<PivotStep[]>(initialType && initialKey ? [{ type: initialType, key: initialKey }] : []);
  const [formType, setFormType] = useState<PivotNodeType>("actor");
  const [formValue, setFormValue] = useState("");

  useEffect(() => {
    if (initialType && initialKey) setPath([{ type: initialType, key: initialKey }]);
  }, [initialType, initialKey]);

  const current = path[path.length - 1] ?? null;
  const { data, isLoading, isError, error } = usePivotChain(current?.type ?? null, current?.key ?? null);

  function pivotTo(type: PivotNodeType, key: string) {
    setPath((prev) => [...prev, { type, key }]);
  }

  function jumpTo(index: number) {
    setPath((prev) => prev.slice(0, index + 1));
  }

  function startNew(e: React.FormEvent) {
    e.preventDefault();
    if (!formValue.trim()) return;
    setPath([{ type: formType, key: formValue.trim() }]);
  }

  const unavailableByType = new Map((data?.unavailableHops ?? []).map((h) => [h.neighborType, h.reason]));

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3">
        <div>
          <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
            <Waypoints className="h-4 w-4 text-primary" />
            Pivot Chain
          </CardTitle>
          <p className="mt-1 text-xs text-muted">Walk Threat Actor → Campaign → Malware → CVE → Victim → IP → Domain → Report, one real link at a time.</p>
        </div>
        <form onSubmit={startNew} className="flex w-full flex-wrap items-center gap-2">
          <Select value={formType} onChange={(e) => setFormType(e.target.value as PivotNodeType)} className="w-44">
            {PIVOT_ORDER.map((t) => (
              <option key={t} value={t}>
                {NODE_TYPE_LABEL[t]}
              </option>
            ))}
          </Select>
          <Input value={formValue} onChange={(e) => setFormValue(e.target.value)} placeholder="e.g. an actor name, CVE ID, IP, domain..." className="min-w-[220px] flex-1" />
          <button type="submit" className="flex h-9 items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 text-sm text-primary hover:border-primary/50">
            <Search className="h-3.5 w-3.5" />
            Start
          </button>
        </form>
        {path.length > 0 && <Breadcrumb items={path.map((step, i) => ({ label: `${NODE_TYPE_LABEL[step.type]}: ${step.key}`, onClick: i < path.length - 1 ? () => jumpTo(i) : undefined }))} />}
      </CardHeader>
      <CardContent>
        {!current ? (
          <p className="text-sm text-muted">Pick a starting node above, or pivot in from another tab, to begin walking the chain.</p>
        ) : isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={error?.message ?? "Pivot Chain is unavailable right now."} />
        ) : data ? (
          <div className="space-y-4">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="default">{NODE_TYPE_LABEL[data.node.type]}</Badge>
                <span className="font-mono text-sm font-semibold text-foreground">{data.node.label}</span>
                {!data.node.found && <Badge variant="muted">Not tracked as a canonical entity in this app yet</Badge>}
              </div>
              {data.node.summary && <p className="mt-1.5 text-xs text-muted">{data.node.summary}</p>}
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {PIVOT_ORDER.filter((t) => t !== data.node.type).map((t) => (
                <NeighborGroup key={t} type={t} edges={data.neighbors[t] ?? []} unavailableReason={unavailableByType.get(t)} onPivot={pivotTo} />
              ))}
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
