import { useQuery } from "@tanstack/react-query";
import { fetchHuntingLibrary } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Read-only, searchable roll-up of every hunting query AI Summarization has generated -- see server/huntingLibrary.js. No status tracking (that's the Detection Backlog's job, see useDetectionBacklog.ts) -- this is a library to browse/copy from, not a workflow. */
export function useHuntingLibrary() {
  return useQuery({
    queryKey: queryKeys.huntingLibrary,
    queryFn: fetchHuntingLibrary,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
