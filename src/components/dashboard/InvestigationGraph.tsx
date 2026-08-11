import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Network,
  UserSearch,
  Crosshair,
  Bug,
  ShieldAlert,
  Building2,
  Router,
  Globe,
  Link as LinkIcon,
  Fingerprint,
  Mail,
  FileText,
  Cpu,
  KeyRound,
  Smartphone,
  Target,
  Flag,
  ExternalLink,
  Sparkles,
  Factory,
  Radar,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { Section, KeyValueBlock, FieldList } from "./reportPrimitives";
import { RelationshipCard } from "./investigation/RelationshipCard";
import { InvestigationLeadsPanel } from "./investigation/InvestigationLeadsPanel";
import { AiGraphInsightsPanel } from "./investigation/AiGraphInsightsPanel";
import { useInvestigationGraph, type PositionedGraphNode, type GraphEdgeWithSource } from "@/hooks/useInvestigationGraph";
import { useGraphInsights } from "@/hooks/useInvestigate";
import type { GraphNodeType, GraphConfidence, InvestigationResult, GraphNodeResult } from "@/types/threat-intel";
import type { AttackTechniqueSummary } from "@/investigation/attackTactics";
import { AttackTechniquesByTactic } from "./investigation/AttackTechniquesByTactic";
import { cn } from "@/lib/utils";

const NODE_TYPE_LABEL: Record<GraphNodeType, string> = {
  actor: "Threat Actor",
  campaign: "Campaign",
  malware: "Malware Family",
  cve: "CVE",
  victim: "Victim / Organization",
  ip: "IP Address",
  domain: "Domain",
  url: "URL",
  hash: "File Hash",
  email: "Email Address",
  fileName: "File Name",
  processName: "Process Name",
  registryKey: "Registry Key",
  userAgent: "User Agent",
  attackTechnique: "ATT&CK Technique",
  country: "Country",
  report: "AI Summarization Report",
  asn: "ASN",
  industry: "Industry",
};

const NODE_TYPE_ICON: Record<GraphNodeType, typeof UserSearch> = {
  actor: UserSearch,
  campaign: Crosshair,
  malware: Bug,
  cve: ShieldAlert,
  victim: Building2,
  ip: Router,
  domain: Globe,
  url: LinkIcon,
  hash: Fingerprint,
  email: Mail,
  fileName: FileText,
  processName: Cpu,
  registryKey: KeyRound,
  userAgent: Smartphone,
  attackTechnique: Target,
  country: Flag,
  report: FileText,
  asn: Network,
  industry: Factory,
};

const CONFIDENCE_STROKE: Record<GraphConfidence, string> = { High: "#3fb950", Medium: "#d29922", Low: "#8b949e" };

// The canvas answers "what is this connected to" -- it should never be
// dominated by dozens of same-type leaves (an actor with 100+ IPs/domains
// drowning out the campaign/malware/victim relationships that actually
// matter; ATT&CK techniques are handled separately, see NodeMetadata below).
// Caps how many edges of the SAME (source, targetType) pair become visible
// canvas nodes/edges, keeping the top N by the edge's own confidenceScore
// (which already folds in a recency bonus -- see investigationGraph.js
// #scoreConfidence -- so more-recently-confirmed relationships surface
// first). Never touches the underlying graph.edges/graph.nodes maps (still
// fully populated) -- the side detail panel's Relationships list and
// InvestigationLeadsPanel's "Continue Investigation" counts (which already
// has its own "+N more" pattern) always show the REAL, uncapped totals.
// Always keeps any edge already pointing at the currently-selected node, so
// clicking through a lead beyond the cap still renders it on canvas.
const CANVAS_EDGES_PER_TYPE = 8;
function edgesVisibleOnCanvas(edges: GraphEdgeWithSource[], nodeKeyOf: (type: GraphNodeType, key: string) => string, selectedId: string | null): GraphEdgeWithSource[] {
  const bySourceType = new Map<string, GraphEdgeWithSource[]>();
  for (const e of edges) {
    const k = `${e.sourceId} ${e.targetType}`;
    if (!bySourceType.has(k)) bySourceType.set(k, []);
    bySourceType.get(k)!.push(e);
  }
  const kept: GraphEdgeWithSource[] = [];
  for (const group of bySourceType.values()) {
    const sorted = [...group].sort((a, b) => b.confidenceScore - a.confidenceScore);
    sorted.forEach((e, i) => {
      if (i < CANVAS_EDGES_PER_TYPE || nodeKeyOf(e.targetType, e.targetKey) === selectedId) kept.push(e);
    });
  }
  return kept;
}

function EntityNode({ data }: NodeProps<Node<{ node: PositionedGraphNode; selected: boolean; loading: boolean }>>) {
  const { node, selected, loading } = data;
  const Icon = NODE_TYPE_ICON[node.type];
  return (
    <div
      className={cn(
        "flex min-w-[160px] max-w-[220px] items-center gap-2 rounded-xl border bg-surface px-3 py-2 shadow-lg transition-colors",
        selected ? "border-primary/70 ring-2 ring-primary/30" : "border-white/10",
        !node.found && "opacity-60"
      )}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <div className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg", selected ? "bg-primary/20 text-primary" : "bg-white/[0.06] text-muted")}>
        {loading ? <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" /> : <Icon className="h-4 w-4" />}
      </div>
      <div className="min-w-0">
        <div className="truncate text-[11px] uppercase tracking-wide text-muted">{NODE_TYPE_LABEL[node.type]}</div>
        <div className="truncate font-mono text-xs font-semibold text-foreground">{node.label}</div>
      </div>
    </div>
  );
}

const NODE_TYPES = { entity: EntityNode };

interface InvestigationGraphProps {
  initialType?: GraphNodeType | null;
  initialKey?: string | null;
  /**
   * The SAME context-aware GraphNodeResult already computed server-side for
   * this search (server/investigation/index.js#computeGraphResult, folded
   * into /investigate's own response) -- carries data a plain re-fetch of
   * `/dashboard/investigation-graph` can never reconstruct, most notably a
   * hash search's live malware-family classification context (see
   * server/investigation/investigationGraph.js#gatherCrossReferenceOnly's
   * `context.malwareFamily` param). Seeding from this (via graph.seed())
   * instead of independently re-fetching (via graph.reset()) is what makes
   * "hash classified but not yet a tracked entity" actually show up here
   * instead of silently being replaced by a context-less duplicate fetch.
   */
  seedResult?: GraphNodeResult | null;
  /** Reused as-is from DashboardPage.tsx -- the same jump-off actions already wired for search-prefill/auto-run into the Triage Console / Campaign / Malware / AI Summarization tabs, and the pre-existing actor search prefill. */
  goToTriageInvestigate: (query: string) => void;
  goToCampaignSearch: (name: string) => void;
  goToMalwareSearch: (name: string) => void;
  goToActorSearch: (name: string) => void;
  goToAiSummarySearch: (title: string) => void;
  /** Passed straight through to the "Re-analyze Full Graph" AI call's context -- the same overview useInvestigationWorkspace's single-node auto-summary already receives. Optional since this component has no overview of its own when not embedded in the Workspace. */
  overview?: InvestigationResult["overview"] | null;
}

function GraphCanvas({ initialType, initialKey, seedResult, goToTriageInvestigate, goToCampaignSearch, goToMalwareSearch, goToActorSearch, goToAiSummarySearch, overview }: InvestigationGraphProps) {
  const graph = useInvestigationGraph();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { setCenter } = useReactFlow();
  const fullGraphInsights = useGraphInsights();
  const [seedId, setSeedId] = useState<string | null>(null);

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<Node>([]);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const visibleEdges = useMemo(
    () => edgesVisibleOnCanvas(Array.from(graph.edges.values()), graph.nodeKey, selectedId),
    [graph.edges, graph.nodeKey, selectedId]
  );
  const visibleNodeIds = useMemo(() => {
    const ids = new Set<string>();
    if (seedId) ids.add(seedId);
    if (selectedId) ids.add(selectedId);
    for (const e of visibleEdges) {
      ids.add(e.sourceId);
      ids.add(graph.nodeKey(e.targetType, e.targetKey));
    }
    return ids;
  }, [visibleEdges, seedId, selectedId, graph.nodeKey]);
  const hiddenEdgeCount = graph.edges.size - visibleEdges.length;

  useEffect(() => {
    if (initialType && initialKey) {
      const id = graph.nodeKey(initialType, initialKey);
      setSelectedId(id);
      setSeedId(id);
      fullGraphInsights.reset();
      // Seed from the already-computed, context-aware result when we have
      // it (always true when embedded in Investigation Workspace -- see
      // seedResult's own doc comment) -- falls back to a plain re-fetch
      // only in the hypothetical case this ever renders without one.
      if (seedResult) graph.seed(initialType, initialKey, seedResult);
      else graph.reset(initialType, initialKey);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialType, initialKey, seedResult]);

  useEffect(() => {
    setRfNodes((prev) => {
      const byId = new Map(prev.map((n) => [n.id, n]));
      const next: Node[] = [];
      for (const [id, gn] of graph.nodes) {
        if (!visibleNodeIds.has(id)) continue;
        const existing = byId.get(id);
        next.push({
          id,
          type: "entity",
          position: existing ? existing.position : { x: gn.x, y: gn.y },
          data: { node: gn, selected: id === selectedId, loading: graph.loadingIds.has(id) },
        });
      }
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph.nodes, graph.loadingIds, selectedId, visibleNodeIds]);

  useEffect(() => {
    setRfEdges(
      visibleEdges.map((e) => ({
        id: `${e.sourceId}->${graph.nodeKey(e.targetType, e.targetKey)}`,
        source: e.sourceId,
        target: graph.nodeKey(e.targetType, e.targetKey),
        label: e.relationship,
        style: { stroke: CONFIDENCE_STROKE[e.confidence], strokeWidth: e.confidence === "High" ? 2 : 1 },
        labelStyle: { fill: "var(--color-muted, #8b949e)", fontSize: 10 },
        animated: false,
      }))
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleEdges]);

  function selectAndExpand(id: string, type: GraphNodeType, key: string) {
    setSelectedId(id);
    void graph.expandNode(type, key);
    const pos = graph.nodes.get(id);
    if (pos) setCenter(pos.x, pos.y, { zoom: 1, duration: 400 });
  }

  function onNodeClick(_: unknown, node: Node) {
    const gn = graph.nodes.get(node.id);
    if (gn) selectAndExpand(node.id, gn.type, gn.id);
  }

  /**
   * Scoped to whatever the analyst has actually built by expanding nodes --
   * every accumulated edge across the whole graph, not just the seed's
   * direct connections. Reuses generateGraphInsights() unchanged (it already
   * operates generically over any edge list); no backend change needed.
   */
  function runFullGraphAnalysis() {
    const seedNode = seedId ? graph.nodes.get(seedId) : null;
    if (!seedNode) return;
    const allEdges = Array.from(graph.edges.values());
    const unavailableRelationships = Array.from(
      new Map(Array.from(graph.unavailableByNode.values()).flat().map((u) => [`${u.relationshipType}:${u.reason}`, u])).values(),
    );
    fullGraphInsights.mutate({ node: seedNode, edges: allEdges, unavailableRelationships, overview: overview ?? null });
  }

  const selectedNode = selectedId ? graph.nodes.get(selectedId) : null;
  const selectedEdges = selectedId ? graph.edgesForNode(selectedId) : [];
  const selectedUnavailable = selectedId ? graph.unavailableByNode.get(selectedId) ?? [] : [];
  const selectedLoading = selectedId ? graph.loadingIds.has(selectedId) : false;
  const selectedError = selectedId ? graph.errorIds.get(selectedId) : undefined;

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3">
        <div className="flex w-full flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
              <Network className="h-4 w-4 text-primary" />
              Investigation Graph
            </CardTitle>
            <p className="mt-1 text-xs text-muted">
              Start from any indicator or entity, then click any node to discover its real relationships and keep pivoting -- every edge shows why it exists, confidence, first/last seen, and supporting sources. MITRE ATT&amp;CK techniques are analytical context, not canvas nodes -- see a selected node's own "MITRE ATT&amp;CK Activity" panel.
            </p>
            {hiddenEdgeCount > 0 && (
              <p className="mt-1 text-xs text-muted">
                Showing the top {CANVAS_EDGES_PER_TYPE} relationship(s) per type on canvas ({hiddenEdgeCount} lower-confidence relationship(s) hidden) -- see "Continue Investigation" on a selected node for the full list.
              </p>
            )}
          </div>
          {graph.nodes.size > 1 && (
            <button
              type="button"
              onClick={runFullGraphAnalysis}
              disabled={fullGraphInsights.isPending}
              className="flex shrink-0 items-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary hover:border-primary/50 disabled:opacity-60"
            >
              <Sparkles className="h-3.5 w-3.5" />
              {fullGraphInsights.isPending ? "Analyzing…" : "Re-analyze Full Graph"}
            </button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {graph.nodes.size === 0 ? (
          <p className="py-12 text-center text-sm text-muted">Building the relationship graph for this search…</p>
        ) : (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_360px]">
            <div className="h-[560px] overflow-hidden rounded-xl border border-white/10 bg-black/20">
              <ReactFlow
                nodes={rfNodes}
                edges={rfEdges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onNodeClick={onNodeClick}
                nodeTypes={NODE_TYPES}
                fitView
                minZoom={0.2}
              >
                <Background gap={24} />
                <Controls showInteractive={false} />
                <MiniMap pannable zoomable className="!bg-surface" />
              </ReactFlow>
            </div>
            <div className="max-h-[560px] overflow-y-auto rounded-xl border border-white/10 bg-white/[0.02] p-3">
              {!selectedNode ? (
                <p className="text-sm text-muted">Click a node to see its details and relationships.</p>
              ) : selectedLoading ? (
                <div className="space-y-2">
                  <Skeleton className="h-6 w-2/3" />
                  <Skeleton className="h-16 w-full" />
                  <Skeleton className="h-16 w-full" />
                </div>
              ) : selectedError ? (
                <ErrorState message={selectedError} />
              ) : (
                <div className="space-y-4">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="default">{NODE_TYPE_LABEL[selectedNode.type]}</Badge>
                      <span className="font-mono text-sm font-semibold text-foreground">{selectedNode.label}</span>
                    </div>
                    {!selectedNode.found && <p className="mt-1 text-xs italic text-muted">Not tracked as a canonical entity in this app yet.</p>}
                    {selectedNode.summary && <p className="mt-1.5 text-xs text-muted">{selectedNode.summary}</p>}
                  </div>

                  <NodeActions node={selectedNode} goToTriageInvestigate={goToTriageInvestigate} goToCampaignSearch={goToCampaignSearch} goToMalwareSearch={goToMalwareSearch} goToActorSearch={goToActorSearch} goToAiSummarySearch={goToAiSummarySearch} />

                  <NodeMetadata node={selectedNode} />

                  <InvestigationLeadsPanel edges={selectedEdges} onSelect={(type, key) => selectAndExpand(graph.nodeKey(type, key), type, key)} />

                  {selectedEdges.length > 0 && (
                    <Section title="Relationships">
                      <div className="space-y-2">
                        {selectedEdges.map((e) => (
                          <RelationshipCard key={`${e.targetType}:${e.targetKey}`} edge={e} onFocus={() => selectAndExpand(graph.nodeKey(e.targetType, e.targetKey), e.targetType, e.targetKey)} />
                        ))}
                      </div>
                    </Section>
                  )}

                  {selectedUnavailable.length > 0 && (
                    <Section title="Not available">
                      <ul className="space-y-1.5 text-xs italic text-muted">
                        {selectedUnavailable.map((u) => (
                          <li key={u.relationshipType}>{u.reason}</li>
                        ))}
                      </ul>
                    </Section>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {(fullGraphInsights.isPending || fullGraphInsights.isSuccess || fullGraphInsights.isError) && (
          <div className="mt-3">
            <AiGraphInsightsPanel
              title="Full Graph Analysis"
              insights={fullGraphInsights.data ?? null}
              pending={fullGraphInsights.isPending}
              error={fullGraphInsights.isError ? (fullGraphInsights.error as Error).message : null}
              onFocusEntity={(entity) => {
                const gn = Array.from(graph.nodes.values()).find((n) => n.label === entity);
                if (gn) selectAndExpand(graph.nodeKey(gn.type, gn.id), gn.type, gn.id);
              }}
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function NodeActions({ node, goToTriageInvestigate, goToCampaignSearch, goToMalwareSearch, goToActorSearch, goToAiSummarySearch }: { node: PositionedGraphNode } & Pick<InvestigationGraphProps, "goToTriageInvestigate" | "goToCampaignSearch" | "goToMalwareSearch" | "goToActorSearch" | "goToAiSummarySearch">) {
  const action = (() => {
    switch (node.type) {
      case "ip":
      case "domain":
      case "url":
      case "hash":
      case "cve":
        return { label: "Investigate in Triage Console", onClick: () => goToTriageInvestigate(node.id) };
      case "actor":
        return { label: "View Full Profile", onClick: () => goToActorSearch(node.label) };
      case "campaign":
        return { label: "View Full Profile", onClick: () => goToCampaignSearch(node.label) };
      case "malware":
        return { label: "View Full Profile", onClick: () => goToMalwareSearch(node.label) };
      case "report":
        return { label: "Open Report", onClick: () => goToAiSummarySearch(node.label) };
      default:
        return null;
    }
  })();
  if (!action) return null;
  return (
    <button type="button" onClick={action.onClick} className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary hover:border-primary/50">
      {action.label}
      <ExternalLink className="h-3 w-3" />
    </button>
  );
}

function NodeMetadata({ node }: { node: PositionedGraphNode }) {
  const meta = (node.metadata ?? {}) as Record<string, unknown>;
  const scalarPairs: Array<[string, string | null]> = [];
  const push = (label: string, v: unknown) => {
    if (v === null || v === undefined || v === "") return;
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") scalarPairs.push([label, String(v)]);
  };
  push("Verified", meta.verified === true ? "Yes" : meta.verified === false ? "No" : null);
  push("Mention count", meta.mentionCount);
  push("IOC sightings", meta.iocSightings);
  push("Actor type", meta.actorType);
  push("Country", meta.country);
  push("Active since", meta.activeSince);
  push("Tactic", meta.tactic);
  push("Sector", meta.sector);
  push("Severity", meta.severity);
  push("Published", meta.publishedDate);

  // Registrar/created/expires/nameservers are already shown in full by
  // KeyFactsPanel and the deeper Indicator-Specific Intelligence section
  // (domainModule.js's own separate RDAP call) for a domain search -- the
  // only thing from this node's metadata that isn't already on this page
  // anywhere is the crt.sh certificate issuer. Same "each fact lives in
  // exactly one place" rule as the rest of this page.
  const certificate = meta.certificate as { latestIssuer?: string | null } | undefined;
  push("Latest Certificate Issuer (crt.sh)", certificate?.latestIssuer);

  const aliases = Array.isArray(meta.aliases) ? (meta.aliases as string[]) : [];
  const detectionRules = Array.isArray(meta.detectionRules) ? (meta.detectionRules as Array<{ label: string; path: string; url: string }>) : [];
  const sourceArticles = Array.isArray(meta.sourceArticles) ? (meta.sourceArticles as Array<{ title: string; link: string; source: string; publishedDate: string }>) : [];
  const huntingQueries = Array.isArray(meta.huntingQueries) ? (meta.huntingQueries as Array<{ platform: string }>) : [];
  // "HOW does this threat operate" -- deliberately kept off the canvas (see
  // server/investigation/investigationGraph.js#attackTechniqueSummaries and
  // the edgesVisibleOnCanvas comment above); shown here, grouped by real
  // MITRE kill-chain tactic, as analytical context for whichever node is
  // currently selected.
  const attackTechniques = Array.isArray(meta.attackTechniques) ? (meta.attackTechniques as AttackTechniqueSummary[]) : [];

  // A live AV/sandbox classification exists for this hash but didn't
  // exact-match any tracked malware entity's name/alias (see server/
  // investigation/investigationGraph.js#matchMalwareFamilyFromLabel) --
  // AV vendor labels are notoriously inconsistent/misspelled across engines,
  // so this is a REAL, common case, not an edge case. Surfaced honestly
  // instead of the canvas silently showing an isolated node with no
  // explanation: this is real evidence the platform found and chose not to
  // fabricate into a graph edge, not an absence of evidence.
  const unmatched = meta.liveFamilyLabelUnmatched as { label: string; source: string } | null | undefined;

  return (
    <>
      {unmatched && (
        <div className="rounded-lg border border-medium/25 bg-medium/[0.06] p-2.5 text-xs">
          <p className="mb-1 flex items-center gap-1.5 font-semibold text-medium">
            <Radar className="h-3.5 w-3.5" /> Live classification, not yet a tracked profile
          </p>
          <p className="text-foreground/90">
            {unmatched.source} classified this as <span className="font-mono">"{unmatched.label}"</span> -- no tracked malware family in this platform's data exactly matches that name/alias, so no relationship edge is drawn. This is a real signal, not a dead end: search "{unmatched.label}" directly, or check Malware Intelligence for a close variant.
          </p>
        </div>
      )}
      <KeyValueBlock title="Details" pairs={scalarPairs} />
      <FieldList title="Aliases" items={aliases} />
      {attackTechniques.length > 0 && (
        <Section title="MITRE ATT&amp;CK Activity">
          <AttackTechniquesByTactic techniques={attackTechniques} compact />
        </Section>
      )}
      {detectionRules.length > 0 && (
        <Section title="Detection Rules">
          <ul className="space-y-1 text-xs">
            {detectionRules.map((r) => (
              <li key={r.path}>
                <a href={r.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                  {r.label}: {r.path}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}
      {huntingQueries.length > 0 && <p className="text-xs text-muted">{huntingQueries.length} hunting quer{huntingQueries.length === 1 ? "y" : "ies"} available in the Hunting &amp; Detection tab.</p>}
      {sourceArticles.length > 0 && (
        <Section title="Source Articles">
          <ul className="space-y-1.5 text-xs">
            {sourceArticles.slice(0, 5).map((a) => (
              <li key={a.link}>
                <a href={a.link} target="_blank" rel="noreferrer" className="text-foreground hover:text-primary hover:underline">
                  {a.title}
                </a>
                <span className="text-muted"> — {a.source} · {a.publishedDate?.slice(0, 10)}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </>
  );
}

/**
 * Analyst-grade Investigation Graph -- replaces the old linear Pivot Chain
 * (Threat Actor -> Campaign -> Malware -> ... one hop at a time, see git
 * history). Start from any entity type, click any node to discover its real
 * relationships and keep pivoting; see server/investigation/
 * investigationGraph.js for what backs every edge. Wrapped in
 * ReactFlowProvider so GraphCanvas can use useReactFlow() to pan the camera
 * to a newly-focused node.
 */
export function InvestigationGraph(props: InvestigationGraphProps) {
  return (
    <ReactFlowProvider>
      <GraphCanvas {...props} />
    </ReactFlowProvider>
  );
}
