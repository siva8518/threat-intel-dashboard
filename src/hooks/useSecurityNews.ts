import { useQuery } from "@tanstack/react-query";
import { fetchNews } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Merged CISA, The Hacker News, BleepingComputer and Krebs on Security headlines, newest first (merged server-side). */
export function useSecurityNews() {
  const query = useQuery({
    queryKey: queryKeys.news,
    queryFn: fetchNews,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  return { items: query.data?.items ?? [], isLoading: query.isLoading, isError: query.isError, error: query.error as Error | null };
}
