import { useQuery } from "@tanstack/react-query";
import { fetchAiThreatSummaries } from "@/api/dashboardApi";
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
