import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { submitSandboxAnalysis, fetchSandboxStatus } from "@/api/dashboardApi";
import { queryKeys } from "./queryKeys";
import type { SandboxRecord } from "@/types/threat-intel";

const POLL_INTERVAL_MS = 8_000;

/**
 * Read side: current sandbox record for one indicator, auto-polling only
 * while a job is genuinely in flight (status "submitted"/"in_progress") --
 * stops polling once the record reaches a terminal status (completed/
 * failed/existing_available/not_analyzed/rate_limited), so an analyst
 * leaving a completed report open doesn't keep hitting the backend forever.
 * Enabled for every sandbox-eligible indicator type (including "hash",
 * where this GET is what actually performs the cheap existing-report
 * check -- see server/routes/dashboard.js's /sandbox/status route).
 *
 * `initialRecord` seeds the cache from the snapshot the /investigate
 * response already computed (result.sandbox.record) so the panel renders
 * immediately without waiting on a second round trip -- the query still
 * takes over polling/refetching from there.
 */
export function useSandboxStatus(type: string | null, value: string | null, initialRecord?: SandboxRecord | null) {
  return useQuery({
    queryKey: queryKeys.sandboxStatus(type ?? "", value ?? ""),
    queryFn: () => fetchSandboxStatus(type as string, value as string),
    enabled: Boolean(type && value),
    initialData: initialRecord ?? undefined,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "submitted" || status === "in_progress" ? POLL_INTERVAL_MS : false;
    },
    retry: 1,
  });
}

/**
 * Write side: the ONLY code path that ever triggers a live sandbox
 * submission -- fired exclusively by the "Analyze in Sandbox" button, never
 * automatically. Invalidates the status query on success so the UI
 * immediately reflects "submitted" and starts polling, instead of waiting
 * for the next natural refetch.
 */
export function useSubmitSandboxAnalysis() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ type, value }: { type: string; value: string }) => submitSandboxAnalysis(type, value),
    onSuccess: (record) => {
      queryClient.setQueryData(queryKeys.sandboxStatus(record.indicatorType, record.indicatorValue), record);
    },
  });
}
