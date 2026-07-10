import { useQuery } from "@tanstack/react-query";
import { fetchTopThreatActorsToday } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Top Threat Actors Today -- see server/topThreatActorsToday.js. */
export function useTopThreatActorsToday() {
  const query = useQuery({
    queryKey: queryKeys.topThreatActorsToday,
    queryFn: fetchTopThreatActorsToday,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
  return { actors: query.data?.actors ?? [], isLoading: query.isLoading, isError: query.isError, error: query.error as Error | null };
}
