import { useMutation } from "@tanstack/react-query";
import { investigate, generateInvestigationAiReport, generateGraphInsights, generateCorrelationSummary, generateShouldICare } from "@/api/dashboardApi";

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

/** Unlike useGenerateInvestigationAiReport above, this one IS fired automatically -- see useInvestigationWorkspace.ts, which calls .mutate() once relationships finish loading, not on a button click. */
export function useGraphInsights() {
  return useMutation({
    mutationFn: generateGraphInsights,
  });
}

/** Also fired automatically, alongside useGraphInsights above -- see useInvestigationWorkspace.ts. Reasons across the full unified investigation result, not just the graph's direct edges. */
export function useCorrelationSummary() {
  return useMutation({
    mutationFn: generateCorrelationSummary,
  });
}

/** Also fired automatically, alongside useCorrelationSummary above -- see useInvestigationWorkspace.ts. The human-centric "Should I Care?" assessment, see server/investigation/shouldICare.js. */
export function useShouldICare() {
  return useMutation({
    mutationFn: generateShouldICare,
  });
}
