import { useQuery } from "@tanstack/react-query";
import { fetchAttackTacticHeatmap } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** ATT&CK Tactic Heat Map -- see server/correlate.js#computeAttackTacticHeatmap. */
export function useAttackTacticHeatmap() {
  return useQuery({
    queryKey: queryKeys.attackTacticHeatmap,
    queryFn: fetchAttackTacticHeatmap,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
