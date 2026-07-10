import { useQuery } from "@tanstack/react-query";
import { fetchDailySummary } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Daily Summary -- see server/dailySummary.js. */
export function useDailySummary() {
  const query = useQuery({
    queryKey: queryKeys.dailySummary,
    queryFn: fetchDailySummary,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
  return { data: query.data, isLoading: query.isLoading, isError: query.isError, error: query.error as Error | null };
}
