// Flattens every AI Summarization report's detectionEngineeringOpportunities
// (see server/aiThreatSummary.js) into a trackable backlog -- the concrete
// "build this detection" gaps a report identifies (new analytics,
// correlation rules, MITRE coverage gaps, telemetry/log-source gaps),
// paired with a status this app has no other way to know (has Detection
// Engineering actually built it yet). Same pattern as
// server/remediationQueue.js + server/remediationTracker.js: the backlog
// items themselves are re-derived from the report store on every request
// (never persisted independently), only the human status decision is.
const CATEGORY_LABELS = {
  newAnalytics: "New Analytics",
  newCorrelationRules: "New Correlation Rules",
  newSigmaRules: "New Sigma Rules",
  newKqlDetections: "New KQL Detections",
  edrBehavioralDetections: "EDR Behavioral Detections",
  siemCorrelationLogic: "SIEM Correlation Logic",
  mitreCoverageGaps: "MITRE Coverage Gaps",
  telemetryGaps: "Telemetry Gaps",
  logSourceRequirements: "Log Source Requirements",
};

export const DETECTION_BACKLOG_CATEGORIES = Object.keys(CATEGORY_LABELS);

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export function buildDetectionBacklog(reports, statuses) {
  const items = [];
  for (const report of reports) {
    const opportunities = report.detectionEngineeringOpportunities;
    if (!opportunities) continue;
    for (const category of DETECTION_BACKLOG_CATEGORIES) {
      const entries = opportunities[category] ?? [];
      entries.forEach((description, index) => {
        const id = `${report.id}::${category}::${index}`;
        const tracked = statuses[id];
        items.push({
          id,
          category,
          categoryLabel: CATEGORY_LABELS[category],
          description,
          status: tracked?.status ?? "open",
          note: tracked?.note ?? null,
          statusUpdatedAt: tracked?.updatedAt ?? null,
          reportId: report.id,
          articleTitle: report.articleTitle,
          articleLink: report.articleLink,
          articleSource: report.articleSource,
          generatedAt: report.generatedAt,
          severity: report.severity,
          cveIds: (report.cves ?? []).map((c) => c.id),
        });
      });
    }
  }
  return items.sort((a, b) => {
    const rankDiff = (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4);
    if (rankDiff !== 0) return rankDiff;
    return new Date(b.generatedAt) - new Date(a.generatedAt);
  });
}
