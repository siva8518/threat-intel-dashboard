import { useEffect, useMemo } from "react";
import { useInvestigate } from "./useInvestigate";
import { useInvestigationGraph } from "./useInvestigationGraph";
import { buildRecommendedActions } from "@/lib/recommendedActions";
import type { CveRecord, GraphNodeType, IndicatorType, InvestigationResult, MalwareIntelligenceEntity, ThreatActorIntelligenceEntity, CampaignIntelligenceEntity, DetectionRuleRef } from "@/types/threat-intel";

const DIRECT_TYPE_MAP: Partial<Record<IndicatorType, GraphNodeType>> = {
  cve: "cve",
  ip: "ip",
  domain: "domain",
  url: "url",
  sha256: "hash",
  sha1: "hash",
  md5: "hash",
  email: "email",
  fileName: "fileName",
  processName: "processName",
  registryKey: "registryKey",
  userAgent: "userAgent",
};

interface EntityModuleData {
  malware?: Array<{ entity: MalwareIntelligenceEntity; detectionRules: DetectionRuleRef[] }>;
  actors?: ThreatActorIntelligenceEntity[];
  campaigns?: CampaignIntelligenceEntity[];
}

/**
 * Which single graph node the Relationships/Recommended-Actions sections
 * should expand for a resolved investigate() result. IOC-shaped types map
 * 1:1 onto a graph node type. `name`-type (malware/actor/campaign search)
 * mirrors server/investigation/entityModule.js's own "best primary match"
 * precedence (lines 32-36: malware first, then APT/ransomware actor, then
 * any actor, then campaign) so the Workspace's single relationship view
 * agrees with which entity the Universal Overview's verdict was computed
 * from -- other buckets that also matched stay reachable via the existing
 * EntityIntelligenceSection chips, just not auto-expanded here.
 */
function resolveGraphTarget(result: InvestigationResult): { type: GraphNodeType; key: string } | null {
  const direct = DIRECT_TYPE_MAP[result.type as IndicatorType];
  if (direct) return { type: direct, key: result.indicator };

  if (result.type === "name") {
    const md = result.moduleData as unknown as EntityModuleData;
    if (md.malware && md.malware.length > 0) return { type: "malware", key: md.malware[0].entity.name };
    const primaryActor = md.actors?.find((a) => a.type === "Ransomware" || a.type === "APT") ?? md.actors?.[0];
    if (primaryActor) return { type: "actor", key: primaryActor.name };
    if (md.campaigns && md.campaigns.length > 0) return { type: "campaign", key: md.campaigns[0].name };
  }

  return null;
}

/**
 * Composes the existing useInvestigate() (verdict/severity/relatedIntelligence)
 * with the existing useInvestigationGraph() (relationship edges + real
 * detection/hunting metadata) into one merged view for the Investigation
 * Workspace -- one search, both systems, no second search box. See
 * src/lib/recommendedActions.ts for the deterministic per-team next-steps
 * layered on top, computed instantly from whatever both systems returned.
 */
export function useInvestigationWorkspace() {
  const investigateM = useInvestigate();
  const graph = useInvestigationGraph();

  const result = investigateM.data;
  const graphTarget = result ? resolveGraphTarget(result) : null;

  useEffect(() => {
    if (graphTarget) graph.reset(graphTarget.type, graphTarget.key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphTarget?.type, graphTarget?.key]);

  const graphNodeId = graphTarget ? graph.nodeKey(graphTarget.type, graphTarget.key) : null;
  const graphNode = graphNodeId ? (graph.nodes.get(graphNodeId) ?? null) : null;
  const graphEdges = graphNodeId ? graph.edgesForNode(graphNodeId) : [];
  const graphUnavailable = graphNodeId ? (graph.unavailableByNode.get(graphNodeId) ?? []) : [];
  const graphLoading = graphNodeId ? graph.loadingIds.has(graphNodeId) : false;
  const graphError = graphNodeId ? graph.errorIds.get(graphNodeId) : undefined;

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
    runInvestigation: (query: string) => investigateM.mutate(query),
  };
}
