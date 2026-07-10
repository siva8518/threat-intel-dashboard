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

export function useGithubIntelStats() {
  return useQuery({
    queryKey: queryKeys.githubIntelStats,
    queryFn: fetchGithubIntelStats,
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
