import { useQuery } from "@tanstack/react-query";
import { fetchGeoTargeting } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Full (unsliced) country list for the World Threat Map -- see server/correlate.js#computeGeoTargeting. */
export function useGeoTargeting() {
  return useQuery({
    queryKey: queryKeys.geoTargeting,
    queryFn: fetchGeoTargeting,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
