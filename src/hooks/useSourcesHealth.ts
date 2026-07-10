import { useQuery } from "@tanstack/react-query";
import { fetchSourcesHealth } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/**
 * Reads real last-synchronized timestamps and online/offline state directly
 * from the backend scheduler (server/scheduler.js + server/cache.js) --
 * this is now ground truth, not inferred from React Query's own cache state
 * the way the browser-driven version had to.
 */
export function useSourcesHealth() {
  const query = useQuery({
    queryKey: queryKeys.health,
    queryFn: fetchSourcesHealth,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  return {
    sources: query.data?.sources ?? [],
    onlineCount: query.data?.onlineCount ?? 0,
    totalCount: query.data?.totalCount ?? 0,
  };
}
