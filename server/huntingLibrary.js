// Flattens every AI Summarization report's threatHuntingOpportunities (see
// server/aiThreatSummary.js) into one searchable, per-platform library.
// Each report already generates real hunting logic grounded in that
// specific article's content (not generic boilerplate -- the prompt
// explicitly rejects that, see SYSTEM_PROMPT), but it's locked inside that
// one report with no way to browse across reports by platform. This is pure
// aggregation, not a new data source or a persisted store: re-derived from
// the report store on every request, since the underlying reports are
// already immutable once generated.
const PLATFORM_LABELS = {
  defenderXdrKql: "Microsoft Defender XDR (KQL)",
  sentinelKql: "Microsoft Sentinel (KQL)",
  splunkSpl: "Splunk (SPL)",
  elastic: "Elastic",
  sigma: "Sigma",
  yara: "YARA",
  crowdstrikeFalcon: "CrowdStrike Falcon",
  carbonBlack: "Carbon Black",
};

export const HUNTING_PLATFORMS = Object.keys(PLATFORM_LABELS);

export function buildHuntingQueryLibrary(reports) {
  const items = [];
  for (const report of reports) {
    const opportunities = report.threatHuntingOpportunities;
    if (!opportunities) continue;
    for (const platform of HUNTING_PLATFORMS) {
      const queries = opportunities[platform] ?? [];
      queries.forEach((query, index) => {
        items.push({
          id: `${report.id}::${platform}::${index}`,
          platform,
          platformLabel: PLATFORM_LABELS[platform],
          query,
          reportId: report.id,
          articleTitle: report.articleTitle,
          articleLink: report.articleLink,
          articleSource: report.articleSource,
          generatedAt: report.generatedAt,
          severity: report.severity,
          cveIds: (report.cves ?? []).map((c) => c.id),
          // "Not Reported" is a real, valid value for this field elsewhere in
          // this app (aiThreatSummary.js's own "never invent facts" grounding
          // uses it as an explicit placeholder when the article names
          // nothing) -- confirmed live it was leaking through here as if it
          // were a real malware family, right next to a genuine one like
          // "Dragonforce Ransomware" on the same badge row.
          malware: (report.malware ?? []).map((m) => m.family).filter((f) => f && f !== "Not Reported"),
          threatActors: (report.threatActors ?? []).map((a) => a.group).filter((g) => g && g !== "Not Reported"),
        });
      });
    }
  }
  return items.sort((a, b) => new Date(b.generatedAt) - new Date(a.generatedAt));
}
