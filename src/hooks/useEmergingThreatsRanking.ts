import { useQuery } from "@tanstack/react-query";
import { fetchEmergingThreatsRanking } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Threat Priority Score ranking + aggregate industry heatmap across every AI Summarization report -- see server/emergingThreatsRanking.js. */
export function useEmergingThreatsRanking() {
  return useQuery({
    queryKey: queryKeys.emergingThreatsRanking,
    queryFn: fetchEmergingThreatsRanking,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
