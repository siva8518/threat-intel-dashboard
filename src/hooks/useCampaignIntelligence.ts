import { useQuery } from "@tanstack/react-query";
import { fetchCampaignIntelligence } from "@/api/dashboardApi";
import { AUTO_REFRESH_MS, STALE_TIME_MS } from "@/config/constants";
import { queryKeys } from "./queryKeys";

/** Canonical, deduped campaign/operation catalog -- see server/campaignIntelligence.js. */
export function useCampaignIntelligence() {
  return useQuery({
    queryKey: queryKeys.campaignIntelligence,
    queryFn: fetchCampaignIntelligence,
    staleTime: STALE_TIME_MS,
    refetchInterval: AUTO_REFRESH_MS,
    retry: 1,
  });
}
