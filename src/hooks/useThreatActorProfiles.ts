import { useQuery } from "@tanstack/react-query";
import { fetchThreatActorList, fetchThreatActorProfile, searchThreatActorProfiles } from "@/api/dashboardApi";
import { STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Full list of ATT&CK groups, for the initial picker view. */
export function useThreatActorList() {
  return useQuery({
    queryKey: queryKeys.threatActorList,
    queryFn: fetchThreatActorList,
    staleTime: STALE_TIME_MS,
    retry: 1,
  });
}

/** Debounced search by actor name or alias -- pass the already-debounced query in. */
export function useThreatActorSearch(query: string) {
  return useQuery({
    queryKey: queryKeys.threatActorSearch(query),
    queryFn: () => searchThreatActorProfiles(query),
    staleTime: STALE_TIME_MS,
    retry: 1,
  });
}

/** Full correlated profile for one actor (ATT&CK + OTX + threat feed + news + NVD). */
export function useThreatActorProfile(attackId: string | null) {
  return useQuery({
    queryKey: queryKeys.threatActorProfile(attackId ?? ""),
    queryFn: () => fetchThreatActorProfile(attackId as string),
    enabled: Boolean(attackId),
    staleTime: STALE_TIME_MS,
    retry: 1,
  });
}
