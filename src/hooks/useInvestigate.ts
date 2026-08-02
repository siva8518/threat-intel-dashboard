import { useMutation } from "@tanstack/react-query";
import { investigate, generateInvestigationAiReport } from "@/api/dashboardApi";

/** On-demand, fired on search submit -- see useIocSearch.ts for the same pattern this replaces (broadened from 4 indicator types to all 16, auto-detected server-side). */
export function useInvestigate() {
  return useMutation({
    mutationFn: (query: string) => investigate(query),
  });
}

/** Separate mutation from useInvestigate -- only fires when the user clicks "Generate AI Report", never automatically alongside the search above. */
export function useGenerateInvestigationAiReport() {
  return useMutation({
    mutationFn: (query: string) => generateInvestigationAiReport(query),
  });
}
