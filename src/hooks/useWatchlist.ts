import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchWatchlist, addWatchlistKeyword, removeWatchlistKeyword } from "@/api/dashboardApi";
import { STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** User-curated list of client/org names being continuously monitored -- see server/watchlist.js. */
export function useWatchlist() {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.watchlist,
    queryFn: fetchWatchlist,
    staleTime: STALE_TIME_MS,
    retry: 1,
  });

  const addMutation = useMutation({
    mutationFn: addWatchlistKeyword,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.watchlist }),
  });

  const removeMutation = useMutation({
    mutationFn: removeWatchlistKeyword,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.watchlist }),
  });

  return {
    keywords: query.data?.keywords ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
    error: query.error,
    addKeyword: addMutation.mutateAsync,
    removeKeyword: removeMutation.mutateAsync,
    isAdding: addMutation.isPending,
  };
}
