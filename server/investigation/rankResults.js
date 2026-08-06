// Deterministic ranking across a search's full merged result set -- reuses
// the same confidence-scoring discipline already established in
// investigationGraph.js#scoreConfidence (recency + supporting-report-count +
// source-count bonuses over a provenance-tier base score) rather than
// inventing a third formula. The graph's own edges already carry a real
// confidenceScore/relationship/reasoning for every relationship this
// platform discovered -- this just flattens and ranks them into one "what
// matters most" list, topped up with any AI Summarization report match that
// isn't already represented as a graph edge.
function reportFinding(report) {
  return {
    label: report.articleTitle,
    entityType: "report",
    relationship: "covered in report",
    // Matches CONFIDENCE_RULES' "Cross-reference:" tier in
    // investigationGraph.js -- same provenance category (a shared indicator
    // matched via this platform's own cross-reference pass), same base score.
    confidenceScore: 52,
    reasoning: `Matched via this platform's own cross-reference against ${report.articleSource}.`,
    lastSeen: report.publishedDate,
    sources: [report.articleSource],
  };
}

function edgeFinding(edge) {
  return {
    label: edge.targetLabel,
    entityType: edge.targetType,
    relationship: edge.relationship,
    confidenceScore: edge.confidenceScore,
    reasoning: edge.reasoning,
    lastSeen: edge.lastSeen,
    sources: edge.sources,
  };
}

/**
 * @param {import("./investigationGraph.js").GraphNodeResult | null} graph
 * @param {ReturnType<import("./crossReference.js").crossReferenceIndicator> | null} crossRef
 * @returns {Array<{label: string, entityType: string, relationship: string, confidenceScore: number, reasoning: string, lastSeen: string | null, sources: string[]}>}
 */
export function rankFindings(graph, crossRef) {
  const findings = [];
  const seen = new Set();

  for (const edge of graph?.edges ?? []) {
    const key = `${edge.targetType}:${edge.targetLabel.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(edgeFinding(edge));
  }

  for (const report of crossRef?.matchingAiReports ?? []) {
    const key = `report:${report.articleTitle.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(reportFinding(report));
  }

  return findings.sort((a, b) => b.confidenceScore - a.confidenceScore || new Date(b.lastSeen ?? 0).getTime() - new Date(a.lastSeen ?? 0).getTime()).slice(0, 25);
}
