import { useQuery } from "@tanstack/react-query";
import { fetchAiProviderHealth, fetchAiUsage } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/**
 * Per-provider health/cooldown status across the full AI fallback chain
 * (server/ai/providerHealth.js) plus rolled-up request/token usage
 * (server/ai/aiRequestLog.js) -- same admin/developer surface as
 * useSourcesHealth, rendered in the Sources tab.
 */
export function useAiProviderHealth() {
  const healthQuery = useQuery({
    queryKey: queryKeys.aiProviderHealth,
    queryFn: fetchAiProviderHealth,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  const usageQuery = useQuery({
    queryKey: queryKeys.aiUsage,
    queryFn: fetchAiUsage,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  return {
    providers: healthQuery.data?.providers ?? [],
    usage: usageQuery.data ?? null,
  };
}
