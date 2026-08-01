import { useQuery } from "@tanstack/react-query";
import { fetchAiThreatSummaries, fetchAiSummaryProvenance } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** SOC-analyst-style structured reports generated from major vendor/CISA advisories -- see server/aiThreatSummaryJob.js. */
export function useAiThreatSummaries() {
  return useQuery({
    queryKey: queryKeys.aiThreatSummaries,
    queryFn: fetchAiThreatSummaries,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}

/** Static section->provenance-label map (never changes at runtime) -- fetched once, cached indefinitely rather than polled. See server/aiThreatSummary.js#REPORT_SECTION_PROVENANCE. */
export function useAiSummaryProvenance() {
  return useQuery({
    queryKey: queryKeys.aiSummaryProvenance,
    queryFn: fetchAiSummaryProvenance,
    staleTime: Infinity,
    retry: 1,
  });
}
