import { useQuery } from "@tanstack/react-query";
import { fetchTodaySecurityEvents } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Top Security Events Today -- see server/todaySecurityEvents.js. */
export function useTodaySecurityEvents() {
  const query = useQuery({
    queryKey: queryKeys.todayEvents,
    queryFn: fetchTodaySecurityEvents,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
  return { data: query.data, isLoading: query.isLoading, isError: query.isError, error: query.error as Error | null };
}
