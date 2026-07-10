import { useQuery } from "@tanstack/react-query";
import { fetchKev } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

export function useKev() {
  return useQuery({
    queryKey: queryKeys.kev,
    queryFn: fetchKev,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
