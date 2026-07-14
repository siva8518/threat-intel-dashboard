import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchFlashReports, markFlashReportRead, markAllFlashReportsRead } from "@/api/dashboardApi";
import { queryKeys } from "./queryKeys";

// Deliberately much shorter than AUTO_REFRESH_MS (15 min) -- these are meant
// to be near-real-time alerts ("tracked and reported immediately" per the
// original ask), and the backend scan itself runs every 3 minutes
// (server/watchlistScanner.js), so polling faster than that wouldn't
// surface anything sooner anyway.
const FLASH_REPORT_POLL_MS = 60 * 1000;

/** Watchlist match feed -- a tracked name found somewhere in the platform's data. See server/watchlistScanner.js. */
export function useFlashReports() {
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.flashReports,
    queryFn: fetchFlashReports,
    refetchInterval: FLASH_REPORT_POLL_MS,
    retry: 1,
  });

  const markReadMutation = useMutation({
    mutationFn: markFlashReportRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.flashReports }),
  });

  const markAllReadMutation = useMutation({
    mutationFn: markAllFlashReportsRead,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.flashReports }),
  });

  return {
    reports: query.data?.reports ?? [],
    unreadCount: query.data?.unreadCount ?? 0,
    isLoading: query.isLoading,
    isError: query.isError,
    markRead: markReadMutation.mutateAsync,
    markAllRead: markAllReadMutation.mutateAsync,
  };
}
