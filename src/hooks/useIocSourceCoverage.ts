import { useQuery } from "@tanstack/react-query";
import { fetchIocSourceCoverage } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Per-source IOC extraction yield diagnostics -- see server/iocExtractionMetrics.js. */
export function useIocSourceCoverage() {
  return useQuery({
    queryKey: queryKeys.iocSourceCoverage,
    queryFn: fetchIocSourceCoverage,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
