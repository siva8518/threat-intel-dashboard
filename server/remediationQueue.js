// Builds the Remediation/Patch Tracker's prioritized CVE queue -- turns the
// same enriched CVE records the Latest CVEs tab already shows into "what
// should Vulnerability Management patch first," by combining three signals
// this app already has for every cached CVE (no LLM call, no new external
// fetch): confirmed active exploitation (KEV), predicted exploitation
// probability (EPSS), and raw severity (CVSS). Deliberately the same
// "transparent weighted heuristic, not an industry-standard metric" spirit
// as server/executiveSummary.js's Critical Threat Level score -- explainable
// and cheap enough to recompute on every request across ~100 cached CVEs,
// unlike the AI Summarization job's own per-article LLM-scored aiRiskScoring
// (server/aiThreatSummary.js), which only exists for the handful of articles
// that have gone through that pipeline.
const KEV_POINTS = 40;
const EPSS_MAX_POINTS = 40;
const CVSS_MAX_POINTS = 20;

export function computeUrgencyScore(cve) {
  const kevPoints = cve.knownExploited ? KEV_POINTS : 0;
  const epssPoints = (cve.epssScore ?? 0) * EPSS_MAX_POINTS;
  const cvssPoints = ((cve.cvssScore ?? 0) / 10) * CVSS_MAX_POINTS;
  return Math.round(kevPoints + epssPoints + cvssPoints);
}

/**
 * AI Summarization (server/aiThreatSummary.js) already asks the model for
 * patch availability/fixed-versions/workarounds per article -- real detail
 * pulled from the vendor's own advisory text, not something worth
 * re-deriving. Only a fraction of cached CVEs have gone through that
 * pipeline yet, so this is a bonus enrichment when available, not a
 * dependency -- a CVE with no matching report just shows "Not yet
 * analyzed" rather than blocking the queue on AI Summarization's own
 * (deliberately slow, see server/aiThreatSummaryJob.js) cadence.
 */
function buildPatchInfoIndex(aiReports) {
  const byId = new Map();
  for (const report of aiReports) {
    for (const cve of report.cves ?? []) {
      if (!byId.has(cve.id)) byId.set(cve.id, report.patchInformationNarrative ?? null);
    }
  }
  return byId;
}

/**
 * @param {Array} cveRecords - already KEV/EPSS-correlated (see server/correlate.js#correlateCves)
 * @param {object} statuses - cveId -> {status, note, updatedAt} (see server/remediationTracker.js#getAllStatuses)
 * @param {Array} aiReports - server/aiThreatSummaryStore.js#getAllReports()
 */
export function buildRemediationQueue(cveRecords, statuses, aiReports) {
  const patchInfoById = buildPatchInfoIndex(aiReports ?? []);

  return cveRecords
    .map((cve) => {
      const tracked = statuses[cve.id];
      return {
        ...cve,
        urgencyScore: computeUrgencyScore(cve),
        status: tracked?.status ?? "pending",
        note: tracked?.note ?? null,
        statusUpdatedAt: tracked?.updatedAt ?? null,
        patchInfo: patchInfoById.get(cve.id) ?? null,
      };
    })
    .sort((a, b) => {
      if (b.urgencyScore !== a.urgencyScore) return b.urgencyScore - a.urgencyScore;
      return new Date(b.publishedDate) - new Date(a.publishedDate);
    });
}
