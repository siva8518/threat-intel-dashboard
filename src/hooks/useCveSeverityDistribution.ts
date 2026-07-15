import { useQuery } from "@tanstack/react-query";
import { fetchCveSeverityDistribution } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/**
 * CVEs published in the last 30 days, bucketed by CVSS v3 severity -- see
 * server/connectors/nvd.js. Polls every 3s while the backend reports
 * `ready: false` (NVD's first sync since server boot hasn't landed yet),
 * instead of the normal 15-minute cadence -- otherwise a page load that lands
 * during that window would show a "no CVEs" empty state for up to 15 minutes
 * even though the real data is usually ready within seconds.
 */
export function useCveSeverityDistribution() {
  return useQuery({
    queryKey: queryKeys.cveSeverityDistribution,
    queryFn: fetchCveSeverityDistribution,
    staleTime: STALE_TIME_MS,
    refetchInterval: (query) => (query.state.data?.ready === false ? 3000 : AUTO_REFRESH_MS),
    retry: 1,
  });
}
