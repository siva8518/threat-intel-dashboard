import { useQuery } from "@tanstack/react-query";
import { fetchCveProfile } from "@/api/dashboardApi";
import { STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Cross-reference correlation for one CVE (actors/campaigns/malware/techniques/IOCs/GitHub PoCs/news). */
export function useCveProfile(cveId: string | null) {
  return useQuery({
    queryKey: queryKeys.cveProfile(cveId ?? ""),
    queryFn: () => fetchCveProfile(cveId as string),
    enabled: Boolean(cveId),
    staleTime: STALE_TIME_MS,
    retry: 1,
  });
}
