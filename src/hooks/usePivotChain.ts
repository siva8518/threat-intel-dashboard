import { useQuery } from "@tanstack/react-query";
import { fetchPivotChain } from "@/api/dashboardApi";
import type { PivotNodeType } from "@/types/threat-intel";
import { queryKeys } from "./queryKeys";

/**
 * One hop of the Pivot Chain -- keyed on [type, key] rather than a mutation
 * (contrast useInvestigate.ts) so stepping "back" to an already-visited node
 * reuses the cache instead of refetching. No auto-refresh: this is
 * navigational, on-demand data, not a live dashboard widget.
 */
export function usePivotChain(type: PivotNodeType | null, key: string | null) {
  return useQuery({
    queryKey: queryKeys.pivotChain(type ?? "", key ?? ""),
    queryFn: () => fetchPivotChain(type as PivotNodeType, key as string),
    enabled: Boolean(type && key),
    staleTime: 60_000,
    retry: 1,
  });
}
