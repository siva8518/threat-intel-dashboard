import { useQuery } from "@tanstack/react-query";
import { fetchVulnCheckKev } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** VulnCheck's Community KEV catalog -- optional, requires VULNCHECK_API_KEY. See server/connectors/vulncheckKev.js. */
export function useVulnCheckKev() {
  return useQuery({
    queryKey: queryKeys.vulncheckKev,
    queryFn: fetchVulnCheckKev,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
