// Task-category labels every aiRouter.summarize()/summarizeJson() caller
// passes as {task}. Two independent things this buys:
//   1. Telemetry (aiRequestLog.js) can answer "which task type consumes the
//      most tokens", not just "which provider".
//   2. AI_TASK_DEFAULTS gives a sensible tier when a caller omits one --
//      but every existing call site that has a real, deliberate reason to
//      want a specific tier or context window already passes it explicitly
//      (e.g. combinedExtraction.js's {tier: "fast"}, aiThreatSummary.js's
//      large {minContextWindow}), and an explicit value always wins. This
//      is a fallback for future callers (e.g. a SOC_ASSISTANT chat surface)
//      that don't yet know to think about tiers, not a reclassification of
//      today's behavior.
//
// Deliberately NOT a per-task model/provider override table: this app's
// providers don't have benchmarked quality rankings across these 11
// categories, and hardcoding "Model X is better at CVE_ANALYSIS" without
// real evidence would be exactly the kind of unfounded assumption the
// architecture review this file is part of was asked to avoid.
export const AI_TASK = {
  SUMMARY: "SUMMARY",
  CORRELATION: "CORRELATION",
  INVESTIGATION: "INVESTIGATION",
  THREAT_ACTOR_ANALYSIS: "THREAT_ACTOR_ANALYSIS",
  MALWARE_ANALYSIS: "MALWARE_ANALYSIS",
  CAMPAIGN_ANALYSIS: "CAMPAIGN_ANALYSIS",
  CVE_ANALYSIS: "CVE_ANALYSIS",
  INDUSTRY_INTELLIGENCE: "INDUSTRY_INTELLIGENCE",
  OPERATIONAL_GUIDANCE: "OPERATIONAL_GUIDANCE",
  DETECTION_ENGINEERING: "DETECTION_ENGINEERING",
  SOC_ASSISTANT: "SOC_ASSISTANT",
};

/** @typedef {{tier?: "fast"|"default", minContextWindow?: number}} AiTaskDefault */

/** @type {Record<string, AiTaskDefault>} */
export const AI_TASK_DEFAULTS = {
  [AI_TASK.SUMMARY]: { tier: "fast" },
  [AI_TASK.CORRELATION]: { tier: "default" },
  [AI_TASK.INVESTIGATION]: { tier: "default" },
  [AI_TASK.THREAT_ACTOR_ANALYSIS]: { tier: "default" },
  [AI_TASK.MALWARE_ANALYSIS]: { tier: "default" },
  [AI_TASK.CAMPAIGN_ANALYSIS]: { tier: "default" },
  [AI_TASK.CVE_ANALYSIS]: { tier: "default" },
  [AI_TASK.INDUSTRY_INTELLIGENCE]: { tier: "default" },
  [AI_TASK.OPERATIONAL_GUIDANCE]: { tier: "default" },
  [AI_TASK.DETECTION_ENGINEERING]: { tier: "default" },
  // Interactive, latency-sensitive by nature -- defaults fast like SUMMARY,
  // ready for the future AI SOC Assistant this architecture is meant to
  // support without another redesign (see the review's design principle).
  [AI_TASK.SOC_ASSISTANT]: { tier: "fast" },
};
