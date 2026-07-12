import { useQuery } from "@tanstack/react-query";
import { fetchThreatActorIntelligence } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Canonical, deduped threat-actor catalog -- see server/threatActorIntelligence.js. */
export function useThreatActorIntelligence() {
  return useQuery({
    queryKey: queryKeys.threatActorIntelligence,
    queryFn: fetchThreatActorIntelligence,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
