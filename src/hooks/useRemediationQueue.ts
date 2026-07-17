import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchRemediationQueue, setRemediationStatus, clearRemediationStatus } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import type { RemediationStatus } from "@/types/threat-intel";
import { queryKeys } from "./queryKeys";

/** Prioritized VM patch queue -- see server/remediationQueue.js. Status/note mutations are optimistic-free (just invalidate + refetch): this list is short enough (~100 CVEs) that a refetch is instant, and status changes are infrequent user actions, not something needing snappier optimistic UI. */
export function useRemediationQueue() {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.remediationQueue,
    queryFn: fetchRemediationQueue,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  const setStatusMutation = useMutation({
    mutationFn: ({ cveId, status, note }: { cveId: string; status: RemediationStatus; note: string | null }) => setRemediationStatus(cveId, status, note),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.remediationQueue }),
  });

  const clearStatusMutation = useMutation({
    mutationFn: clearRemediationStatus,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.remediationQueue }),
  });

  return {
    items: query.data?.items ?? [],
    ready: query.data?.ready ?? false,
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error,
    setStatus: setStatusMutation.mutateAsync,
    clearStatus: clearStatusMutation.mutateAsync,
    isUpdating: setStatusMutation.isPending || clearStatusMutation.isPending,
  };
}
