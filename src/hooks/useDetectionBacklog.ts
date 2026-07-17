import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchDetectionBacklog, setDetectionBacklogStatus, clearDetectionBacklogStatus } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import type { DetectionBacklogStatus } from "@/types/threat-intel";
import { queryKeys } from "./queryKeys";

/** Detection Engineering's own trackable backlog -- see server/detectionBacklog.js. Same query+mutation shape as useRemediationQueue.ts. */
export function useDetectionBacklog() {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.detectionBacklog,
    queryFn: fetchDetectionBacklog,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  const setStatusMutation = useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: DetectionBacklogStatus; note: string | null }) => setDetectionBacklogStatus(id, status, note),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.detectionBacklog }),
  });

  const clearStatusMutation = useMutation({
    mutationFn: clearDetectionBacklogStatus,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.detectionBacklog }),
  });

  return {
    items: query.data?.items ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error,
    setStatus: setStatusMutation.mutateAsync,
    clearStatus: clearStatusMutation.mutateAsync,
    isUpdating: setStatusMutation.isPending || clearStatusMutation.isPending,
  };
}
