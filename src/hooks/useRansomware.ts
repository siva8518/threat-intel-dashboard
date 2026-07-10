import { useQuery } from "@tanstack/react-query";
import { fetchRansomwareCampaigns, fetchThreatActors } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Recent ransomware-group leak-site posts (ransomware.live) -- ransomware groups only, not APT/nation-state actors. */
export function useRansomwareCampaigns() {
  const query = useQuery({
    queryKey: queryKeys.ransomware,
    queryFn: fetchRansomwareCampaigns,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
  return { campaigns: query.data?.campaigns ?? [], isLoading: query.isLoading, isError: query.isError };
}

/** Ransomware groups + OTX pulse "adversary" tags merged into one activity list. */
export function useThreatActors() {
  return useQuery({
    queryKey: queryKeys.threatActors,
    queryFn: fetchThreatActors,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
