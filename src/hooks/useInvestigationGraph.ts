import { useCallback, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { fetchInvestigationGraphNode } from "@/api/dashboardApi";
import type { GraphEdge, GraphNode, GraphNodeResult, GraphNodeType } from "@/types/threat-intel";
import { queryKeys } from "./queryKeys";

function nodeKey(type: GraphNodeType, key: string) {
  return `${type}:${key.trim().toLowerCase()}`;
}

export interface GraphEdgeWithSource extends GraphEdge {
  sourceId: string;
}

export interface PositionedGraphNode extends GraphNode {
  x: number;
  y: number;
}

const RADIAL_STEP = 260;

/** Places each newly-discovered node in a ring around the node that just discovered it -- computed once per node id (never recomputed on later expands), so InvestigationGraph.tsx's canvas can freely let the user drag a node afterward without this hook fighting it. */
function layoutRing(sourcePos: { x: number; y: number }, index: number, total: number) {
  const angle = (2 * Math.PI * index) / Math.max(total, 1);
  return { x: sourcePos.x + RADIAL_STEP * Math.cos(angle), y: sourcePos.y + RADIAL_STEP * Math.sin(angle) };
}

/**
 * Accumulating graph state for the Investigation Graph -- NOT a single
 * useQuery, since the whole point is that expanding node after node keeps
 * growing one canvas (unlike the old linear Pivot Chain, which only ever
 * queried the single current node). Each `expandNode` call fetches (via
 * React Query's cache, so re-expanding an already-loaded node is free) and
 * merges the result into the accumulated node/edge maps, deduped by
 * `type:key`. `reset` clears everything and starts a fresh graph from one
 * seed node.
 */
export function useInvestigationGraph() {
  const queryClient = useQueryClient();
  const [nodes, setNodes] = useState<Map<string, PositionedGraphNode>>(new Map());
  const [edges, setEdges] = useState<Map<string, GraphEdgeWithSource>>(new Map());
  const [unavailableByNode, setUnavailableByNode] = useState<Map<string, Array<{ relationshipType: string; reason: string }>>>(new Map());
  const [loadingIds, setLoadingIds] = useState<Set<string>>(new Set());
  const [errorIds, setErrorIds] = useState<Map<string, string>>(new Map());
  const loadedRef = useRef<Set<string>>(new Set());
  const positionsRef = useRef<Map<string, { x: number; y: number }>>(new Map());

  /**
   * Merges an already-fetched (or freshly-fetched) GraphNodeResult into the
   * accumulated node/edge maps -- shared by `seed()` (result already in
   * hand, e.g. inlined into /investigate's response) and `expandNode()`
   * (result comes from its own network fetch). One implementation, so a
   * seeded node and an expanded node are positioned/merged identically.
   */
  const mergeGraphResult = useCallback((id: string, result: GraphNodeResult) => {
    loadedRef.current.add(id);
    if (!positionsRef.current.has(id)) positionsRef.current.set(id, { x: 0, y: 0 }); // seed node only -- every other node gets positioned below, relative to whichever node discovered it
    const sourcePos = positionsRef.current.get(id)!;

    const newTargetIds = result.edges.map((e) => nodeKey(e.targetType, e.targetKey)).filter((targetId) => !positionsRef.current.has(targetId));
    const uniqueNewTargets = Array.from(new Set(newTargetIds));
    uniqueNewTargets.forEach((targetId, i) => positionsRef.current.set(targetId, layoutRing(sourcePos, i, uniqueNewTargets.length)));

    setEdges((prev) => {
      const next = new Map(prev);
      for (const e of result.edges) {
        const edgeId = `${id}->${nodeKey(e.targetType, e.targetKey)}`;
        next.set(edgeId, { ...e, sourceId: id });
      }
      return next;
    });
    // Placeholder nodes for not-yet-expanded targets -- lets the canvas
    // render them immediately; clicking one calls expandNode, which
    // overwrites the placeholder with the real fetched node (found/
    // summary/metadata) once it resolves. Position is set once above and
    // never recomputed, so a user drag on an already-placed node is never
    // fought by a later expand elsewhere in the graph.
    setNodes((prev) => {
      const next = new Map(prev);
      next.set(id, { ...result.node, ...positionsRef.current.get(id)! });
      for (const e of result.edges) {
        const targetId = nodeKey(e.targetType, e.targetKey);
        if (!next.has(targetId)) {
          next.set(targetId, { type: e.targetType, id: e.targetKey, label: e.targetLabel, summary: null, found: true, metadata: null, ...positionsRef.current.get(targetId)! });
        }
      }
      return next;
    });
    setUnavailableByNode((prev) => {
      const next = new Map(prev);
      next.set(id, result.unavailableRelationships);
      return next;
    });
  }, []);

  const expandNode = useCallback(
    async (type: GraphNodeType, key: string, { force = false }: { force?: boolean } = {}) => {
      const id = nodeKey(type, key);
      if (!force && loadedRef.current.has(id)) return;

      setLoadingIds((prev) => new Set(prev).add(id));
      setErrorIds((prev) => {
        const next = new Map(prev);
        next.delete(id);
        return next;
      });

      try {
        const result = await queryClient.fetchQuery({
          queryKey: queryKeys.investigationGraphNode(type, key),
          queryFn: () => fetchInvestigationGraphNode(type, key),
          staleTime: 60_000,
        });
        mergeGraphResult(id, result);
      } catch (err) {
        setErrorIds((prev) => new Map(prev).set(id, err instanceof Error ? err.message : "Failed to expand node"));
      } finally {
        setLoadingIds((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      }
    },
    [queryClient, mergeGraphResult]
  );

  const reset = useCallback(
    (type: GraphNodeType, key: string) => {
      loadedRef.current = new Set();
      positionsRef.current = new Map();
      setNodes(new Map());
      setEdges(new Map());
      setUnavailableByNode(new Map());
      setErrorIds(new Map());
      void expandNode(type, key);
    },
    [expandNode]
  );

  /**
   * Seeds the graph from a result the caller already has in hand (e.g.
   * /investigate's inlined `graph` field) -- no network fetch. Also
   * primes React Query's own cache for this node so a later `expandNode`
   * re-visit (e.g. clicking back to the seed node) is free, same as if it
   * had been fetched normally. `result.additionalNodes` (entity-type
   * searches only -- see investigationGraph.js#getExpandedGraph) is merged
   * right after the seed, one node at a time, through the exact same
   * `mergeGraphResult` -- each additional node's own key already has a
   * placeholder position assigned during the seed merge (since the seed's
   * own edges already point at it), so this is what makes the graph open
   * already showing 2 hops instead of requiring a click per hop.
   */
  const seed = useCallback(
    (type: GraphNodeType, key: string, result: GraphNodeResult) => {
      const id = nodeKey(type, key);
      loadedRef.current = new Set();
      positionsRef.current = new Map();
      setNodes(new Map());
      setEdges(new Map());
      setUnavailableByNode(new Map());
      setErrorIds(new Map());
      queryClient.setQueryData(queryKeys.investigationGraphNode(type, key), result);
      mergeGraphResult(id, result);
      for (const extra of result.additionalNodes ?? []) {
        const extraId = nodeKey(extra.seedType, extra.seedKey);
        queryClient.setQueryData(queryKeys.investigationGraphNode(extra.seedType, extra.seedKey), extra);
        mergeGraphResult(extraId, extra);
      }
    },
    [queryClient, mergeGraphResult]
  );

  const edgesForNode = useCallback((id: string) => Array.from(edges.values()).filter((e) => e.sourceId === id), [edges]);

  return useMemo(
    () => ({ nodes, edges, unavailableByNode, loadingIds, errorIds, expandNode, reset, seed, edgesForNode, nodeKey }),
    [nodes, edges, unavailableByNode, loadingIds, errorIds, expandNode, reset, seed, edgesForNode]
  );
}
