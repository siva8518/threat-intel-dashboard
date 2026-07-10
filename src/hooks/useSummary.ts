import { useQuery } from "@tanstack/react-query";
import { fetchSummary } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

export interface SummaryMetric {
  id: "critical-cves-30d" | "new-cves-24h" | "kev" | "malicious-urls" | "sources-online";
  label: string;
  value: number | null;
  isLoading: boolean;
  isError: boolean;
}

/**
 * Aggregates the data behind the summary cards -- already computed
 * server-side. Split across two homes in the UI: the CVE-specific metrics
 * (critical-cves-30d, new-cves-24h) head the "Latest CVEs" tab
 * (CveStatsHeader), the rest stay on the homepage (SummaryCards) -- both
 * read this same query, so there's no duplicate fetch.
 */
export function useSummary() {
  const query = useQuery({
    queryKey: queryKeys.summary,
    queryFn: fetchSummary,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  const data = query.data;
  const base = { isLoading: query.isLoading, isError: query.isError };
  const metrics: SummaryMetric[] = [
    { id: "critical-cves-30d", label: "Critical CVEs (30d)", value: data?.criticalCves30d ?? null, ...base },
    { id: "new-cves-24h", label: "New CVEs (24h)", value: data?.newCves24h ?? null, ...base },
    { id: "kev", label: "Known Exploited Vulnerabilities", value: data?.knownExploitedVulnerabilities ?? null, ...base },
    { id: "malicious-urls", label: "Malicious URLs (recent)", value: data?.maliciousUrls ?? null, ...base },
    { id: "sources-online", label: "Sources Online", value: data?.sourcesOnline ?? null, ...base },
  ];

  return { metrics, sourcesTotal: data?.sourcesTotal ?? 0 };
}
