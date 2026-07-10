import { useMutation } from "@tanstack/react-query";
import { searchIoc } from "@/api/dashboardApi";
import type { IocSearchIndicatorType } from "@/types/threat-intel";

/**
 * On-demand only -- unlike every other hook in this app, this is a mutation
 * (fired on search submit), not a polled query. It fans out live to
 * OTX/AbuseIPDB/VirusTotal/GreyNoise/Shodan server-side (whichever are
 * configured and support the indicator type) and returns one correlated
 * verdict, since none of those sources have a free bulk feed to poll.
 */
export function useIocSearch() {
  return useMutation({
    mutationFn: ({ type, value }: { type: IocSearchIndicatorType; value: string }) => searchIoc(type, value),
  });
}
