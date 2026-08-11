import { useMutation, useQuery } from "@tanstack/react-query";
import { investigate, startInvestigationAiReport, fetchInvestigationAiReportStatus, generateGraphInsights, generateCorrelationSummary, generateShouldICare } from "@/api/dashboardApi";
import { queryKeys } from "./queryKeys";

/** On-demand, fired on search submit -- see useIocSearch.ts for the same pattern this replaces (broadened from 4 indicator types to all 16, auto-detected server-side). */
export function useInvestigate() {
  return useMutation({
    mutationFn: (query: string) => investigate(query),
  });
}

const AI_REPORT_POLL_INTERVAL_MS = 3_000;

/**
 * Submit+poll pair for the "Generate AI Report" button -- see
 * startInvestigationAiReport's own comment for why this isn't a single
 * mutation anymore (DigitalOcean's edge timeout vs. real LLM generation
 * time). useSubmitInvestigationAiReport kicks the job off and hands back a
 * jobId; useInvestigationAiReportJob polls status only while genuinely
 * pending, same shape as useSandboxAnalysis.ts's useSandboxStatus.
 */
export function useSubmitInvestigationAiReport() {
  return useMutation({
    mutationFn: (query: string) => startInvestigationAiReport(query),
  });
}

export function useInvestigationAiReportJob(jobId: string | null) {
  return useQuery({
    queryKey: queryKeys.aiReportJobStatus(jobId ?? ""),
    queryFn: () => fetchInvestigationAiReportStatus(jobId as string),
    enabled: Boolean(jobId),
    refetchInterval: (query) => (query.state.data?.status === "pending" ? AI_REPORT_POLL_INTERVAL_MS : false),
    retry: 1,
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
