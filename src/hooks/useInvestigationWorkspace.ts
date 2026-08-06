import { useEffect, useMemo, useRef } from "react";
import { useInvestigate, useGraphInsights, useCorrelationSummary } from "./useInvestigate";
import { useInvestigationGraph } from "./useInvestigationGraph";
import { buildRecommendedActions } from "@/lib/recommendedActions";
import type { CveRecord, GraphNodeType } from "@/types/threat-intel";

/**
 * Composes the existing useInvestigate() (verdict/severity/relatedIntelligence,
 * now also carrying the seed Investigation Graph node computed server-side
 * in the same pass -- see server/investigation/index.js#computeGraphResult)
 * with useInvestigationGraph()'s accumulating multi-hop canvas state into one
 * merged view for the Investigation Workspace -- one search, no second
 * network round trip for the graph, no second search box. See
 * src/lib/recommendedActions.ts for the deterministic per-team next-steps
 * layered on top, computed instantly from whatever both systems returned.
 */
export function useInvestigationWorkspace() {
  const investigateM = useInvestigate();
  const graph = useInvestigationGraph();
  const insightsM = useGraphInsights();
  const correlationM = useCorrelationSummary();
  const insightsFiredRef = useRef<Set<string>>(new Set());
  const correlationFiredRef = useRef<Set<string>>(new Set());
  const lastGraphNodeIdRef = useRef<string | null>(null);

  const result = investigateM.data;
  const graphTarget: { type: GraphNodeType; key: string } | null = result?.graph ? { type: result.graph.node.type, key: result.graph.node.id } : null;

  useEffect(() => {
    if (graphTarget && result?.graph) graph.seed(graphTarget.type, graphTarget.key, result.graph);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphTarget?.type, graphTarget?.key]);

  const graphNodeId = graphTarget ? graph.nodeKey(graphTarget.type, graphTarget.key) : null;
  const graphNode = graphNodeId ? (graph.nodes.get(graphNodeId) ?? null) : null;
  const graphEdges = graphNodeId ? graph.edgesForNode(graphNodeId) : [];
  const graphUnavailable = graphNodeId ? (graph.unavailableByNode.get(graphNodeId) ?? []) : [];
  const graphLoading = graphNodeId ? graph.loadingIds.has(graphNodeId) : false;
  const graphError = graphNodeId ? graph.errorIds.get(graphNodeId) : undefined;

  /**
   * Auto-fires the AI Investigation Summary the moment this node's
   * relationships finish loading -- explicitly requested to run
   * automatically, unlike useGenerateInvestigationAiReport (manual button
   * only). Guarded so it fires exactly once per resolved node (re-focusing
   * an already-analyzed node, e.g. via a relationship card, doesn't re-fire
   * the LLM call) and skipped entirely when there's nothing real to
   * synthesize (no edges and the entity itself wasn't found).
   */
  useEffect(() => {
    if (graphNodeId !== lastGraphNodeIdRef.current) {
      lastGraphNodeIdRef.current = graphNodeId;
      insightsM.reset();
    }
    if (!graphNodeId || graphLoading || !graphNode) return;
    if (graphEdges.length === 0 && !graphNode.found) return;
    if (insightsFiredRef.current.has(graphNodeId)) return;
    insightsFiredRef.current.add(graphNodeId);
    insightsM.mutate({ node: graphNode, edges: graphEdges, unavailableRelationships: graphUnavailable, overview: result?.overview ?? null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphNodeId, graphLoading, graphNode?.found, graphEdges.length]);

  /**
   * Auto-fires the AI Correlation Summary the moment a search result comes
   * back -- unlike the AI Investigation Summary above, this doesn't need to
   * wait on the graph hook's own state since `result.graph` (and
   * `result.coverage`/`result.rankedFindings`) are already fully populated
   * in the same /investigate response (see server/investigation/index.js).
   * Guarded the same way -- fires once per resolved search, skipped when
   * there's nothing real to synthesize.
   */
  useEffect(() => {
    if (!result) return;
    const key = `${result.type}:${result.indicator.toLowerCase()}`;
    if (correlationFiredRef.current.has(key)) return;
    if (result.coverage.nothingFound) return;
    correlationFiredRef.current.add(key);
    correlationM.mutate(result);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result]);

  const recommendedActions = useMemo(() => {
    if (!result) return null;
    return buildRecommendedActions({
      overview: result.overview,
      relatedIntelligence: result.relatedIntelligence,
      graphNode,
      graphEdges,
      knownExploited: (result.moduleData?.cve as CveRecord | undefined)?.knownExploited,
    });
  }, [result, graphNode, graphEdges]);

  return {
    investigateM,
    result,
    graphTarget,
    graphNode,
    graphEdges,
    graphUnavailable,
    graphLoading,
    graphError,
    recommendedActions,
    graphInsights: insightsM.data ?? null,
    graphInsightsPending: insightsM.isPending,
    graphInsightsError: insightsM.isError ? (insightsM.error as Error).message : null,
    correlationSummary: correlationM.data ?? null,
    correlationSummaryPending: correlationM.isPending,
    correlationSummaryError: correlationM.isError ? (correlationM.error as Error).message : null,
    runInvestigation: (query: string) => investigateM.mutate(query),
  };
}
