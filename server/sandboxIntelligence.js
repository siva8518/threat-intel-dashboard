// Canonical sandbox-analysis store -- one record per indicator, tracking
// whether it has ever been checked/submitted and what came back. Same
// lifecycle contract as the other entity/intelligence stores (server/
// iocIntelligence.js / malwareIntelligence.js / ...): load()/persist() to a
// flat JSON file, upsert, get. This is the ONE place that decides "have we
// already submitted this" -- server/routes/dashboard.js's submit route reads
// it before ever calling a provider, so the same indicator is never
// double-submitted (the literal "Do not submit the same IOC repeatedly"
// requirement).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_DIR = path.join(__dirname, ".cache");
const STORE_PATH = path.join(STORE_DIR, "sandbox-intelligence.json");

// A completed report doesn't change after the fact, so it's cached
// effectively forever -- this constant only bounds how long a NON-terminal
// status (e.g. a job that silently vanished server-side without ever
// reaching "completed"/"failed") is treated as still meaningful before a
// fresh submission is allowed again.
const STALE_IN_PROGRESS_MS = 30 * 60 * 1000; // 30 minutes

let state = load();

function load() {
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, "utf-8"));
    return { records: Array.isArray(parsed.records) ? parsed.records : [] };
  } catch {
    return { records: [] }; // missing file (first run) or corrupt JSON -- start fresh rather than crash
  }
}

function persist() {
  fs.mkdirSync(STORE_DIR, { recursive: true });
  fs.writeFileSync(STORE_PATH, JSON.stringify(state), "utf-8");
}

function normalizeValue(type, value) {
  const v = (value ?? "").toString().trim();
  return type === "domain" || type === "email" || type === "sha256" || type === "sha1" || type === "md5" ? v.toLowerCase() : v;
}

function recordId(type, value) {
  return `${type}:${normalizeValue(type, value)}`;
}

function defaultRecord(type, value) {
  return {
    indicatorType: type,
    indicatorValue: normalizeValue(type, value),
    status: "not_analyzed",
    provider: null,
    jobId: null,
    submittedAt: null,
    completedAt: null,
    report: null,
    error: null,
    // HYBRID_ANALYSIS_* classification (see server/sandbox/
    // hybridAnalysisDiagnostics.js) -- lets the UI render a specific,
    // accurate failure reason instead of a generic "Analysis Failed" for
    // every kind of error. null until a failure is actually recorded.
    errorClassification: null,
    // {isEdgeOrWafBlock, status, headers, bodySnippet} captured at failure
    // time -- the evidence an analyst needs to tell "my app is broken" apart
    // from "the network path to this provider is blocked" without reading
    // server logs. null until a failure is actually recorded.
    diagnostics: null,
    // When this indicator's Hybrid Analysis check was last actually
    // attempted (success or failure) -- lets the status route retry a
    // "failed" hash after a cooldown instead of returning the same stale
    // failure forever (the literal fix for a real gap: once a hash check
    // failed once, it could never self-heal even after the underlying
    // cause -- a bad API key, a rate limit -- was fixed).
    lastAttemptAt: null,
  };
}

/**
 * Read-only lookup -- never touches the network, never mutates the store.
 * Returns a fresh `not_analyzed` shape (not persisted) when nothing exists
 * yet, so every caller can treat the return value as always-present.
 * @returns {import("../src/types/threat-intel.js").SandboxRecord}
 */
export function getSandboxRecord(type, value) {
  const id = recordId(type, value);
  const existing = state.records.find((r) => recordId(r.indicatorType, r.indicatorValue) === id);
  return existing ? { ...existing } : defaultRecord(type, value);
}

/**
 * Whether a NEW submission should be blocked because a live/complete one
 * already covers this indicator -- the dedup check the submit route must
 * call before ever reaching a provider.
 */
export function hasActiveOrCompletedRecord(type, value) {
  const record = getSandboxRecord(type, value);
  if (record.status === "completed" || record.status === "existing_available") return true;
  if (record.status === "submitted" || record.status === "in_progress") {
    const since = record.submittedAt ? Date.now() - new Date(record.submittedAt).getTime() : Infinity;
    return since < STALE_IN_PROGRESS_MS;
  }
  return false;
}

function upsert(type, value, patch) {
  const id = recordId(type, value);
  let record = state.records.find((r) => recordId(r.indicatorType, r.indicatorValue) === id);
  if (!record) {
    record = defaultRecord(type, value);
    state.records.push(record);
  }
  Object.assign(record, patch);
  persist();
  return { ...record };
}

/** An existing report found via a check-only lookup (e.g. a hash overview hit) -- never counted as "we submitted", since nothing was submitted. */
export function recordExistingReport(type, value, report, provider) {
  return upsert(type, value, { status: "existing_available", provider, report, completedAt: report?.analyzedAt ?? new Date().toISOString(), error: null, errorClassification: null, diagnostics: null, lastAttemptAt: new Date().toISOString() });
}

// A hash check is a cheap, read-only GET (unlike a submission, which
// consumes real sandbox quota) -- retrying a previously-failed hash after
// this cooldown lets the record self-heal once the underlying cause (a bad
// API key, a rate limit, a transient network block) is fixed, without
// hammering the upstream on every single page view. The circuit breaker
// (server/sandbox/sandboxProviderHealth.js) still applies underneath this
// -- if it's open, the retry attempt fails fast rather than hitting the
// network anyway.
const FAILED_HASH_RETRY_COOLDOWN_MS = 60_000;

/** Whether a "failed" hash record is old enough to retry -- see FAILED_HASH_RETRY_COOLDOWN_MS. Always true for "not_analyzed" (nothing to cool down from). */
export function isHashCheckDue(type, value) {
  if (type !== "hash") return false;
  const record = getSandboxRecord(type, value);
  if (record.status === "not_analyzed") return true;
  if (record.status !== "failed") return false;
  if (!record.lastAttemptAt) return true;
  return Date.now() - new Date(record.lastAttemptAt).getTime() >= FAILED_HASH_RETRY_COOLDOWN_MS;
}

export function recordSubmission(type, value, { provider, jobId }) {
  return upsert(type, value, { status: "submitted", provider, jobId, submittedAt: new Date().toISOString(), completedAt: null, report: null, error: null });
}

export function recordInProgress(type, value) {
  return upsert(type, value, { status: "in_progress" });
}

export function recordCompleted(type, value, report) {
  return upsert(type, value, { status: "completed", report, completedAt: new Date().toISOString(), error: null, errorClassification: null, diagnostics: null });
}

/**
 * @param {string} type
 * @param {string} value
 * @param {unknown} error
 * @param {{classification?: string, isEdgeOrWafBlock?: boolean, headers?: Record<string,string>, bodySnippet?: string}} [classified] From classifyHybridAnalysisFailure() -- optional so existing callers that don't yet classify still work.
 */
export function recordFailed(type, value, error, classified) {
  return upsert(type, value, {
    status: "failed",
    error: error?.message ?? String(error),
    errorClassification: classified?.classification ?? error?.classification ?? null,
    diagnostics: classified ? { isEdgeOrWafBlock: classified.isEdgeOrWafBlock ?? false, status: error?.status ?? null, headers: classified.headers ?? {}, bodySnippet: classified.bodySnippet ?? "" } : null,
    lastAttemptAt: new Date().toISOString(),
  });
}

export function recordRateLimited(type, value, error) {
  return upsert(type, value, { status: "rate_limited", error: error?.message ?? String(error), errorClassification: "HYBRID_ANALYSIS_RATE_LIMITED", lastAttemptAt: new Date().toISOString() });
}

/**
 * The one place "does this IP appear inside a sandbox report we already
 * have" is answered -- an IP is never submitted directly (see
 * server/sandboxApplicability.js), so this is its only real sandbox signal:
 * scanning every completed report's own networkConnections for a match.
 * Cheap in-memory scan, no network I/O.
 */
export function findSandboxReportsObservingIp(ip) {
  const target = (ip ?? "").toString().trim();
  if (!target) return [];
  return state.records
    .filter((r) => r.status === "completed" && r.report?.networkConnections?.some((c) => c.ip === target))
    .map((r) => ({ ip: target, jobId: r.jobId, provider: r.provider, indicatorType: r.indicatorType, indicatorValue: r.indicatorValue }));
}

/** Same purpose as findSandboxReportsObservingIp above, for a domain observed via a sandboxed sample's own DNS queries -- feeds a domain node's graph edges in server/investigation/investigationGraph.js. */
export function findSandboxReportsObservingDomain(domain) {
  const target = (domain ?? "").toString().trim().toLowerCase();
  if (!target) return [];
  return state.records
    .filter((r) => r.status === "completed" && r.report?.dnsQueries?.some((d) => (d.domain ?? "").toLowerCase() === target))
    .map((r) => ({ domain: target, jobId: r.jobId, provider: r.provider, indicatorType: r.indicatorType, indicatorValue: r.indicatorValue }));
}
