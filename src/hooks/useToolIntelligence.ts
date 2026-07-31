import { useQuery } from "@tanstack/react-query";
import { fetchToolIntelligence } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Canonical, deduped malicious/dual-use tool catalog -- see server/toolIntelligence.js. */
export function useToolIntelligence() {
  return useQuery({
    queryKey: queryKeys.toolIntelligence,
    queryFn: fetchToolIntelligence,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
