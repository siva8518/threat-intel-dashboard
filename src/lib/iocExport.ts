// CSV/JSON export of an Industry Intelligence IOC feed, so analysts can
// operationalize the indicators (import into a SIEM/TIP, block list, etc.).
// Reuses the same blob-download primitive AI Summarization's report export
// already established (src/lib/reportExport.ts) rather than a new mechanism.
import type { IndustryIocFeed, IndustryName } from "@/types/threat-intel";
import { safeFilename, triggerDownload } from "@/lib/reportExport";

function csvField(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

export function buildIocCsv(feed: IndustryIocFeed): string {
  const header = ["indicator", "indicatorType", "malwareFamily", "firstSeen"];
  const rows = feed.indicators.map((ioc) =>
    [ioc.indicator, ioc.indicatorType, ioc.malwareFamily ?? "", ioc.firstSeen ?? ""].map(csvField).join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

export function buildIocJson(feed: IndustryIocFeed): string {
  return JSON.stringify(feed.indicators, null, 2);
}

export function downloadIocFeedAsCsv(industry: IndustryName, feed: IndustryIocFeed) {
  const blob = new Blob([buildIocCsv(feed)], { type: "text/csv;charset=utf-8" });
  triggerDownload(blob, `${safeFilename(industry)}-ioc-feed.csv`);
}

export function downloadIocFeedAsJson(industry: IndustryName, feed: IndustryIocFeed) {
  const blob = new Blob([buildIocJson(feed)], { type: "application/json;charset=utf-8" });
  triggerDownload(blob, `${safeFilename(industry)}-ioc-feed.json`);
}
