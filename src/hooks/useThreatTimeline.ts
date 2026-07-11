import { useQuery } from "@tanstack/react-query";
import { fetchThreatTimeline } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Interactive Threat Timeline -- see server/threatTimeline.js. */
export function useThreatTimeline(days: number) {
  const query = useQuery({
    queryKey: queryKeys.threatTimeline(days),
    queryFn: () => fetchThreatTimeline(days),
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
  return { events: query.data?.events ?? [], isLoading: query.isLoading, isError: query.isError, error: query.error as Error | null };
}
