// Shared row-building logic for the "Operational Guidance" table -- one
// place so the live AiSummarization.tsx view and the PDF/Word export
// (reportExport.ts) can never drift out of sync with each other. Composes
// 6 team rows entirely client-side from two already-distinct backend
// fields: operationalRecommendations (the flat, prioritized "what to do"
// checklist) supplies Priority/Recommended Action/Rationale, and
// operationalActions' per-team sub-objects (the deep "how exactly"
// narrative -- real telemetry, KQL/Sigma/SPL, hunting hypotheses, IR
// steps) supply Detailed Guidance/Telemetry/Detection Opportunities/
// Immediate Next Steps. No backend/prompt change was needed for this merge:
// both source fields already existed and are already deduplicated against
// each other by the system prompt's own "don't repeat across sections"
// instruction -- this only routes each into the right column. Team-name
// spelling differs between the two backend fields ("SOC Operations" in the
// flat list vs. the `socAnalyst` object key, etc.) -- normalized once here.
import type { AiThreatSummaryReport } from "@/types/threat-intel";

// Reports generated before the v2 schema won't have operationalActions at
// all -- fall back to all-empty rather than crashing.
export const EMPTY_BEHAVIORAL_INDICATORS = {
  networkBehaviors: [] as string[],
  processBehaviors: [] as string[],
  authenticationAnomalies: [] as string[],
  dnsActivity: [] as string[],
  powershellActivity: [] as string[],
  scheduledTasks: [] as string[],
  registryModifications: [] as string[],
  persistenceIndicators: [] as string[],
};

export const EMPTY_PLATFORM_RECOMMENDATIONS = {
  logSourcesToReview: [] as string[],
  microsoftDefenderRecommendations: [] as string[],
  microsoftSentinelRecommendations: [] as string[],
  firewallDnsRecommendations: [] as string[],
  emailSecurityRecommendations: [] as string[],
  identityMonitoringRecommendations: [] as string[],
  edrRecommendations: [] as string[],
  userRecommendations: [] as string[],
};

export const EMPTY_OPERATIONAL_ACTIONS = {
  socAnalyst: { telemetryToCheck: [] as string[], whatToLookFor: "Not Reported", immediateNextStep: "Not Reported" },
  recommendedActions: [] as Array<{ action: string; applicable: boolean; details: string }>,
  platformRecommendations: EMPTY_PLATFORM_RECOMMENDATIONS,
  threatHunter: {
    hypotheses: [] as Array<{ hypothesis: string; dataSources: string[]; positiveFindingLooksLike: string; falsePositiveNote: string }>,
    behavioralIndicators: EMPTY_BEHAVIORAL_INDICATORS,
  },
  detectionEngineer: {
    existingRulesAvailable: [] as string[],
    recommendedAction: "Not Reported",
    yaraApplicable: null as string | null,
    kqlOpportunities: [] as string[],
    sigmaOpportunities: [] as string[],
    splOpportunities: [] as string[],
    newDetectionLogic: [] as string[],
    logSourcesRequired: [] as string[],
    expectedFalsePositives: "Not Reported",
    detectionGaps: [] as string[],
    likelyManifestation: "Not Reported",
    behavioralDetectionOpportunities: [] as string[],
  },
  vulnerabilityManagement: {
    applicable: false,
    affectedAssetsSummary: "Not Applicable",
    internetFacing: "Not Applicable",
    exploitMaturity: "Not Applicable",
    patchPriority: "Not Applicable",
    maintenanceWindowRecommendation: "Not Applicable",
    businessCriticality: "Not Applicable",
    compensatingControls: [] as string[],
    knownWorkaround: null as string | null,
  },
  incidentResponse: { immediateTriageSteps: [] as string[], containmentActions: [] as string[], recoveryActions: [] as string[] },
  threatIntelTakeaway: "Not Reported",
  executiveLeadershipTakeaway: "Not Reported",
};

export interface OperationalGuidanceRow {
  team: string;
  priority: string;
  actions: string[];
  detailedGuidance: string[];
  telemetry: string[];
  detectionOpportunities: string[];
  nextSteps: string;
  rationale: string[];
}

const PRIORITY_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
/** Highest-urgency priority across a team's recommendation entries -- the row's single priority badge when that team has several distinct action items at different priorities. */
function highestPriority(priorities: string[]): string {
  return priorities.reduce((best, p) => ((PRIORITY_RANK[p] ?? 9) < (PRIORITY_RANK[best] ?? 9) ? p : best), "Low");
}

export function buildOperationalGuidanceRows(report: AiThreatSummaryReport): OperationalGuidanceRow[] {
  const recs = report.operationalRecommendations ?? [];
  const actions = report.operationalActions ?? EMPTY_OPERATIONAL_ACTIONS;
  const byTeam = (team: string) => recs.filter((r) => r.team === team && r.recommendation !== "No additional actions identified");

  const socRecs = byTeam("SOC Operations");
  const tiRecs = byTeam("Threat Intelligence");
  const thRecs = byTeam("Threat Hunting");
  const deRecs = byTeam("Detection Engineering");
  const vmRecs = byTeam("Vulnerability Management");
  const irRecs = byTeam("Incident Response");

  const applicableChecklist = actions.recommendedActions.filter((a) => a.applicable).map((a) => `${a.action}: ${a.details}`);
  const bi = actions.threatHunter.behavioralIndicators ?? EMPTY_BEHAVIORAL_INDICATORS;
  const behavioralSignals = [
    ...bi.networkBehaviors, ...bi.processBehaviors, ...bi.authenticationAnomalies, ...bi.dnsActivity,
    ...bi.powershellActivity, ...bi.scheduledTasks, ...bi.registryModifications, ...bi.persistenceIndicators,
  ];
  const vm = actions.vulnerabilityManagement;

  return [
    {
      team: "SOC Analyst",
      priority: highestPriority(socRecs.map((r) => r.priority)),
      actions: socRecs.map((r) => r.recommendation),
      detailedGuidance: actions.socAnalyst.whatToLookFor && actions.socAnalyst.whatToLookFor !== "Not Reported" ? [actions.socAnalyst.whatToLookFor] : [],
      telemetry: actions.socAnalyst.telemetryToCheck,
      detectionOpportunities: applicableChecklist,
      nextSteps: actions.socAnalyst.immediateNextStep,
      rationale: socRecs.map((r) => r.rationale),
    },
    {
      team: "Threat Intelligence",
      priority: highestPriority(tiRecs.map((r) => r.priority)),
      actions: tiRecs.map((r) => r.recommendation),
      detailedGuidance: actions.threatIntelTakeaway && actions.threatIntelTakeaway !== "Not Reported" ? [actions.threatIntelTakeaway] : [],
      telemetry: [],
      detectionOpportunities: [],
      nextSteps: tiRecs[0]?.recommendation ?? "Not Reported",
      rationale: tiRecs.map((r) => r.rationale),
    },
    {
      team: "Threat Hunter",
      priority: highestPriority(thRecs.map((r) => r.priority)),
      actions: thRecs.map((r) => r.recommendation),
      detailedGuidance: actions.threatHunter.hypotheses.map((h) => h.hypothesis),
      telemetry: [...new Set(actions.threatHunter.hypotheses.flatMap((h) => h.dataSources))],
      detectionOpportunities: behavioralSignals,
      nextSteps: actions.threatHunter.hypotheses[0]?.positiveFindingLooksLike ?? "Not Reported",
      rationale: thRecs.map((r) => r.rationale),
    },
    {
      team: "Detection Engineer",
      priority: highestPriority(deRecs.map((r) => r.priority)),
      actions: deRecs.map((r) => r.recommendation),
      detailedGuidance: actions.detectionEngineer.likelyManifestation && actions.detectionEngineer.likelyManifestation !== "Not Reported" ? [actions.detectionEngineer.likelyManifestation] : [],
      telemetry: actions.detectionEngineer.logSourcesRequired,
      detectionOpportunities: [
        ...actions.detectionEngineer.existingRulesAvailable,
        ...(actions.detectionEngineer.kqlOpportunities ?? []),
        ...(actions.detectionEngineer.sigmaOpportunities ?? []),
        ...(actions.detectionEngineer.splOpportunities ?? []),
        ...actions.detectionEngineer.newDetectionLogic,
      ],
      nextSteps: actions.detectionEngineer.recommendedAction,
      rationale: deRecs.map((r) => r.rationale),
    },
    {
      team: "Vulnerability Management",
      priority: highestPriority(vmRecs.map((r) => r.priority)),
      actions: vmRecs.map((r) => r.recommendation),
      detailedGuidance: vm.applicable
        ? [vm.affectedAssetsSummary, `Exploit maturity: ${vm.exploitMaturity}`, `Business criticality: ${vm.businessCriticality}`].filter((s) => s && !s.endsWith("Not Reported") && !s.endsWith("Not Applicable"))
        : [],
      telemetry: [],
      detectionOpportunities: vm.compensatingControls,
      nextSteps: vm.applicable ? `Patch priority: ${vm.patchPriority}. ${vm.maintenanceWindowRecommendation}` : "Not Applicable -- this article does not involve a specific CVE.",
      rationale: vmRecs.map((r) => r.rationale),
    },
    {
      team: "Incident Response",
      priority: highestPriority(irRecs.map((r) => r.priority)),
      actions: irRecs.map((r) => r.recommendation),
      detailedGuidance: [...actions.incidentResponse.containmentActions, ...actions.incidentResponse.recoveryActions],
      telemetry: [],
      detectionOpportunities: [],
      nextSteps: actions.incidentResponse.immediateTriageSteps[0] ?? "Not Reported",
      rationale: irRecs.map((r) => r.rationale),
    },
  ];
}
