import { useQuery } from "@tanstack/react-query";
import { fetchCves } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import type { Severity } from "@/types/threat-intel";
import { queryKeys } from "./queryKeys";

export interface CveTableParams {
  severity?: Severity;
  keyword?: string;
  page: number; // 0-based
  pageSize: number;
}

/**
 * Paginated, filterable CVEs. The default (no filter, page 0) view is served
 * from the backend's cache; anything filtered/paginated is answered live --
 * see server/routes/dashboard.js and server/connectors/nvd.js, which is also
 * where the "latest CVEs was showing the oldest ones" reverse-pagination fix
 * now lives (moved server-side, not re-implemented here).
 */
export function useCves(params: CveTableParams) {
  const paramsKey = JSON.stringify(params);

  return useQuery({
    queryKey: queryKeys.cves(paramsKey),
    queryFn: () => fetchCves({ severity: params.severity, keyword: params.keyword, page: params.page, pageSize: params.pageSize }),
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    placeholderData: (previous) => previous,
    retry: 1,
  });
}
