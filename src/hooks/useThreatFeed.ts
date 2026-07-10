import { useQuery } from "@tanstack/react-query";
import { fetchThreatFeed } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/**
 * Already deduped/merged server-side across URLHaus, ThreatFox, MalwareBazaar,
 * Feodo Tracker, OpenPhish and OTX (see server/correlate.js dedupeIocs) -- an
 * indicator seen in more than one source shows up once with a combined
 * `sources` list instead of as duplicate rows. Per-source availability is
 * reported by useSourcesHealth, not here.
 */
export function useThreatFeed() {
  const query = useQuery({
    queryKey: queryKeys.threatFeed,
    queryFn: fetchThreatFeed,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });

  return { iocs: query.data?.iocs ?? [], isLoading: query.isLoading, isError: query.isError, error: query.error as Error | null };
}
