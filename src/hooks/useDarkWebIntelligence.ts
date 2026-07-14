import { useQuery } from "@tanstack/react-query";
import { fetchDarkWebIntelligence } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Canonical, deduped dark-web-finding catalog -- see server/darkWebIntelligence.js. */
export function useDarkWebIntelligence() {
  return useQuery({
    queryKey: queryKeys.darkWebIntelligence,
    queryFn: fetchDarkWebIntelligence,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
