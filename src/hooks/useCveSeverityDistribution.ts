import { useQuery } from "@tanstack/react-query";
import { fetchCveSeverityDistribution } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** CVEs published in the last 30 days, bucketed by CVSS v3 severity -- see server/connectors/nvd.js. */
export function useCveSeverityDistribution() {
  return useQuery({
    queryKey: queryKeys.cveSeverityDistribution,
    queryFn: fetchCveSeverityDistribution,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
