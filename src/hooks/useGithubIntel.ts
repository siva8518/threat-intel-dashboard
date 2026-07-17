import { useQuery } from "@tanstack/react-query";
import { fetchGithubIntelList, fetchGithubIntelStats, fetchGithubRepoDetail, type GithubIntelListParams } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

export function useGithubIntelList(params: GithubIntelListParams) {
  const paramsKey = JSON.stringify(params);
  return useQuery({
    queryKey: queryKeys.githubIntelList(paramsKey),
    queryFn: () => fetchGithubIntelList(params),
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}

/** `days` (null = all-time) scopes only the topCves portion of this response -- see server/routes/dashboard.js's /github-intel/stats handler. */
export function useGithubIntelStats(days: number | null = null) {
  return useQuery({
    queryKey: queryKeys.githubIntelStats(days),
    queryFn: () => fetchGithubIntelStats(days),
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}

export function useGithubRepoDetail(fullName: string | null) {
  return useQuery({
    queryKey: queryKeys.githubRepoDetail(fullName ?? ""),
    queryFn: () => fetchGithubRepoDetail(fullName as string),
    enabled: Boolean(fullName),
    staleTime: STALE_TIME_MS,
    retry: 1,
  });
}
