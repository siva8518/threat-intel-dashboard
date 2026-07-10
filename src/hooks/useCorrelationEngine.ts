import { useQuery } from "@tanstack/react-query";
import { fetchCorrelationEngine } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Unified Intelligence Cards -- see server/correlationEngine.js. */
export function useCorrelationEngine() {
  const query = useQuery({
    queryKey: queryKeys.correlationEngine,
    queryFn: fetchCorrelationEngine,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
  return { cards: query.data?.cards ?? [], isLoading: query.isLoading, isError: query.isError, error: query.error };
}
