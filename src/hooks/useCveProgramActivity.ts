import { useQuery } from "@tanstack/react-query";
import { fetchCveProgramActivity } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Recently added/updated CVE IDs straight from the CVE Program's own cve.org feed -- distinct from NVD's enriched records. */
export function useCveProgramActivity() {
  return useQuery({
    queryKey: queryKeys.cveProgramActivity,
    queryFn: fetchCveProgramActivity,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
