import { useMutation } from "@tanstack/react-query";
import { fetchIndustryBriefing } from "@/api/dashboardApi";
import type { IndustryName } from "@/types/threat-intel";

/**
 * On-demand only, same pattern as useIocSearch -- fired when a user clicks
 * "Generate Full Briefing" on an Industry Heatmap row, not polled. Each of
 * the 10 sectors is a fresh, live Groq generation (see
 * server/industryBriefing.js), so most sectors in a given session are never
 * requested at all -- a mutation, not a query, avoids paying for all 10.
 */
export function useIndustryBriefing() {
  return useMutation({
    mutationFn: (industry: IndustryName) => fetchIndustryBriefing(industry),
  });
}
