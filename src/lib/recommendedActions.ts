// Deterministic, instant "what should each team do next" -- the one thing
// the LLM-generated AiInvestigationReport.operationalGuidance already
// covers, but only on-demand (manual "Generate AI Report" click, can take up
// to a minute -- see server/investigationAi.js). The Investigation Workspace
// needs a real answer the moment a search resolves, not after an optional
// LLM call, so this reuses the exact same already-fetched facts
// (verdict/severity/confidence, matched malware/actor/campaign, real
// detection rules, KEV status) and turns them into short, concrete
// recommendations -- never a generic filler line. When there's no real
// signal to act on, the line says so explicitly (same honesty convention as
// server/investigation/ipModule.js's `internalInvestigation.message`),
// rather than inventing urgency.
import type { GraphEdge, GraphNode, InvestigationRelatedIntelligence, UniversalOverview } from "@/types/threat-intel";

export interface RecommendedActions {
  soc: string[];
  detectionEngineering: string[];
  threatIntelligence: string[];
  incidentResponse: string[];
}

interface RecommendedActionsInput {
  overview: UniversalOverview;
  relatedIntelligence: InvestigationRelatedIntelligence | null;
  graphNode: GraphNode | null;
  graphEdges: GraphEdge[];
  /** CVE-type only -- server/cveModule.js's moduleData.cve.knownExploited (CISA KEV). */
  knownExploited?: boolean;
}

function fmtDate(iso: string | null): string {
  if (!iso) return "an unspecified date";
  return iso.slice(0, 10);
}

export function buildRecommendedActions({ overview, relatedIntelligence, graphNode, graphEdges, knownExploited }: RecommendedActionsInput): RecommendedActions {
  const rel = relatedIntelligence;
  const meta = (graphNode?.metadata ?? {}) as { detectionRules?: unknown[]; huntingQueries?: unknown[] };
  const detectionRules = meta.detectionRules ?? [];
  const huntingQueries = meta.huntingQueries ?? [];
  const infraEdges = graphEdges.filter((e) => e.targetType === "ip" || e.targetType === "domain" || e.targetType === "url" || e.targetType === "hash");
  const victimEdges = graphEdges.filter((e) => e.targetType === "victim");
  const hasAnySignal = Boolean(
    (rel && (rel.matchedMalwareFamilies.length > 0 || rel.associatedThreatActors.length > 0 || rel.activeCampaigns.length > 0 || rel.matchingAiReports.length > 0)) ||
      graphEdges.length > 0 ||
      overview.overallVerdict !== "unknown"
  );

  // --- SOC ---
  const soc: string[] = [];
  if (overview.overallVerdict === "critical" || overview.overallVerdict === "high") {
    soc.push(`Escalate immediately — rated ${overview.severity} severity with ${overview.confidence.toLowerCase()} confidence (${overview.recommendedPriority.toLowerCase()} priority).`);
  } else if (overview.overallVerdict === "medium") {
    soc.push(`Monitor — rated ${overview.severity} severity, ${overview.confidence.toLowerCase()} confidence. No immediate escalation required unless additional signal appears.`);
  } else if (!hasAnySignal) {
    soc.push("No corroborating signal found in this platform's own data — treat as informational unless external context justifies escalation.");
  } else {
    soc.push(`Rated ${overview.severity} severity — log and continue monitoring for corroborating activity.`);
  }
  if (overview.associatedThreatActors.length > 0) soc.push(`Cross-check against known TTPs of ${overview.associatedThreatActors.join(", ")}.`);
  if (overview.activeCampaigns.length > 0) soc.push(`Correlate with ongoing campaign(s): ${overview.activeCampaigns.join(", ")}.`);
  if (victimEdges.length > 0) soc.push(`${victimEdges.length} known victim organization(s) already tracked for this activity — check for overlap with your own sector.`);

  // --- Detection Engineering ---
  const detectionEngineering: string[] = [];
  if (detectionRules.length > 0) {
    const labels = (detectionRules as Array<{ label: string; path: string }>).slice(0, 3).map((r) => `${r.label}: ${r.path}`);
    detectionEngineering.push(`Deploy existing public rule(s): ${labels.join("; ")} — verify against current environment before enabling in blocking mode.`);
  } else if (overview.overallVerdict === "critical" || overview.overallVerdict === "high") {
    detectionEngineering.push("No existing public Sigma/YARA rule found for this indicator or its associated family — draft a custom detection.");
  } else {
    detectionEngineering.push("No existing public detection rule found yet.");
  }
  if (huntingQueries.length > 0) {
    const platforms = Array.from(new Set((huntingQueries as Array<{ platform: string }>).map((q) => q.platform)));
    detectionEngineering.push(`Prebuilt hunting queries available for ${platforms.join(", ")} — see the Hunting & Detection tab.`);
  }
  if (overview.mitreAttackMapping.length > 0) {
    detectionEngineering.push(`Map coverage against ${overview.mitreAttackMapping.length} associated ATT&CK technique(s): ${overview.mitreAttackMapping.slice(0, 5).map((t) => t.id).join(", ")}.`);
  }

  // --- Threat Intelligence ---
  const threatIntelligence: string[] = [];
  if (overview.associatedThreatActors.length > 0) {
    threatIntelligence.push(`Monitor ${overview.associatedThreatActors.join(", ")} for further activity — actively tracked in this platform (indicator last seen ${fmtDate(overview.lastSeen)}).`);
  }
  if (overview.activeCampaigns.length > 0) {
    threatIntelligence.push(`Track campaign(s) ${overview.activeCampaigns.join(", ")} for scope or victim expansion.`);
  }
  if (rel && rel.matchingAiReports.length > 0) {
    threatIntelligence.push(`${rel.matchingAiReports.length} existing AI Summarization report(s) already cover related activity — review before duplicating analysis.`);
  }
  if (rel && rel.matchedMalwareFamilies.length > 0 && overview.associatedThreatActors.length === 0 && overview.activeCampaigns.length === 0) {
    threatIntelligence.push(`Linked to malware family ${rel.matchedMalwareFamilies.join(", ")} with no attributed actor or campaign yet — flag for enrichment.`);
  }
  if (threatIntelligence.length === 0) threatIntelligence.push("No actor or campaign attribution yet — flag for enrichment if this indicator recurs.");

  // --- Incident Response ---
  const incidentResponse: string[] = [];
  if (knownExploited) incidentResponse.push("KEV-listed (CISA Known Exploited Vulnerabilities) — prioritize patching/mitigation per CISA KEV deadlines.");
  if (infraEdges.length > 0) {
    incidentResponse.push(`Check environment for exposure to ${infraEdges.length} related indicator(s) from the same malware family or infrastructure — see Relationships below.`);
  }
  if ((overview.overallVerdict === "critical" || overview.overallVerdict === "high") && (overview.indicatorType === "ip" || overview.indicatorType === "domain" || overview.indicatorType === "url" || overview.indicatorType === "name")) {
    incidentResponse.push("If observed in your environment: isolate affected host(s), capture forensic artifacts, and use the Relationship Graph to identify lateral infrastructure.");
  }
  if (incidentResponse.length === 0) {
    incidentResponse.push("This platform has no SIEM/EDR integration — validate environment exposure manually.");
  }

  return { soc, detectionEngineering, threatIntelligence, incidentResponse };
}
