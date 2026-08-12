// In-memory circuit breaker + health tracking for sandbox providers (today:
// Hybrid Analysis only), same pattern as server/ai/providerHealth.js's
// circuit breaker for the AI provider chain -- deliberately in-memory, not
// persisted, since a cooldown is only meaningful relative to this process's
// clock and a fresh deploy legitimately warrants a clean slate.
//
// The concrete problem this solves: without a breaker, every single
// investigation search that touches a hash/URL/domain re-attempts a live
// Hybrid Analysis call even when the last 20 calls in a row all failed the
// exact same way (e.g. a persistent edge/WAF block) -- wasting latency on
// every request and burning API quota on calls that were never going to
// succeed. After enough CONSECUTIVE forbidden/network-level failures, this
// breaker opens and callers get an immediate, clearly-labeled "circuit
// open" result instead of a real network round-trip.
import { HA_FAILURE } from "./hybridAnalysisDiagnostics.js";

// Only these two reasons ever escalate to a long-lived "circuit open" state
// -- a network block (FORBIDDEN with an edge/WAF signature) or genuine
// unreachability is a structural condition that won't self-resolve on the
// next request, unlike a single timeout or one rate-limit hit.
const CIRCUIT_OPENING_REASONS = new Set([HA_FAILURE.FORBIDDEN, HA_FAILURE.NETWORK_ERROR]);
const CONSECUTIVE_FAILURES_TO_OPEN_CIRCUIT = 3;
const CIRCUIT_OPEN_COOLDOWN_MS = 10 * 60_000; // re-probe every 10 minutes rather than staying open forever

const MAX_DIAGNOSTIC_SAMPLES = 5;

/** @type {Map<string, ReturnType<typeof freshState>>} */
const state = new Map();

function freshState() {
  return {
    consecutiveFailures: 0,
    consecutiveFailureReason: null,
    circuitOpenUntil: null,
    lastSuccessAt: null,
    lastFailureAt: null,
    lastClassification: null,
    lastHumanSummary: null,
    totalSuccess: 0,
    totalFailure: 0,
    countsByClassification: {},
    recentDiagnostics: [], // last N {at, classification, isEdgeOrWafBlock, headers, bodySnippet, status} -- the actual evidence for root-causing the issue
  };
}

function getOrCreate(label) {
  if (!state.has(label)) state.set(label, freshState());
  return state.get(label);
}

/** Whether `label`'s circuit is currently open (skip the network call entirely). */
export function isCircuitOpen(label) {
  const s = state.get(label);
  return Boolean(s?.circuitOpenUntil && s.circuitOpenUntil > Date.now());
}

export function circuitOpenRemainingMs(label) {
  const s = state.get(label);
  if (!s?.circuitOpenUntil) return 0;
  return Math.max(0, s.circuitOpenUntil - Date.now());
}

export function recordSandboxSuccess(label) {
  const s = getOrCreate(label);
  s.consecutiveFailures = 0;
  s.consecutiveFailureReason = null;
  s.circuitOpenUntil = null;
  s.lastSuccessAt = Date.now();
  s.totalSuccess += 1;
}

/**
 * @param {string} label
 * @param {{classification: string, isEdgeOrWafBlock: boolean, humanSummary: string}} classified
 * @param {{status?: number, headers?: Record<string,string>, bodySnippet?: string}} [diagnostics]
 */
export function recordSandboxFailure(label, classified, diagnostics = {}) {
  const s = getOrCreate(label);
  s.lastFailureAt = Date.now();
  s.lastClassification = classified.classification;
  s.lastHumanSummary = classified.humanSummary;
  s.totalFailure += 1;
  s.countsByClassification[classified.classification] = (s.countsByClassification[classified.classification] ?? 0) + 1;

  s.recentDiagnostics.push({ at: new Date().toISOString(), classification: classified.classification, isEdgeOrWafBlock: classified.isEdgeOrWafBlock, ...diagnostics });
  if (s.recentDiagnostics.length > MAX_DIAGNOSTIC_SAMPLES) s.recentDiagnostics.shift();

  if (classified.classification === s.consecutiveFailureReason) {
    s.consecutiveFailures += 1;
  } else {
    s.consecutiveFailures = 1;
    s.consecutiveFailureReason = classified.classification;
  }

  if (CIRCUIT_OPENING_REASONS.has(classified.classification) && s.consecutiveFailures >= CONSECUTIVE_FAILURES_TO_OPEN_CIRCUIT) {
    s.circuitOpenUntil = Date.now() + CIRCUIT_OPEN_COOLDOWN_MS;
  }
}

/** Full diagnostic snapshot -- the evidence base for GET /api/dashboard/sandbox/health. */
export function getSandboxHealthSnapshot(label) {
  const s = state.get(label) ?? freshState();
  const total = s.totalSuccess + s.totalFailure;
  return {
    label,
    circuitOpen: isCircuitOpen(label),
    circuitOpenRemainingMs: circuitOpenRemainingMs(label),
    consecutiveFailures: s.consecutiveFailures,
    consecutiveFailureReason: s.consecutiveFailureReason,
    totalSuccess: s.totalSuccess,
    totalFailure: s.totalFailure,
    successRate: total > 0 ? Math.round((s.totalSuccess / total) * 100) : null,
    countsByClassification: s.countsByClassification,
    lastSuccessAt: s.lastSuccessAt ? new Date(s.lastSuccessAt).toISOString() : null,
    lastFailureAt: s.lastFailureAt ? new Date(s.lastFailureAt).toISOString() : null,
    lastClassification: s.lastClassification,
    lastHumanSummary: s.lastHumanSummary,
    recentDiagnostics: s.recentDiagnostics,
  };
}
