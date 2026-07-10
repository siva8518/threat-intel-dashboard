import { useQuery } from "@tanstack/react-query";
import { fetchExecutiveSummary } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Hero-level threat rollup, recomputed live on every request from already-cached sources. */
export function useExecutiveSummary() {
  return useQuery({
    queryKey: queryKeys.executiveSummary,
    queryFn: fetchExecutiveSummary,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
