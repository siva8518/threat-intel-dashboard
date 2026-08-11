// Hybrid Analysis (Falcon Sandbox) v2 sandbox provider -- implements the
// SandboxProvider contract (see server/sandbox/index.js). This is the only
// file in the app that knows Hybrid Analysis's actual request/response
// shapes; every other module (evidence.js, investigationGraph.js,
// actionability.js, the routes, the UI) only ever sees the normalized
// SandboxReport shape this file produces.
//
// Two genuinely different HA capabilities are wired here:
//  - Existing-hash check: reuses server/lookups/hybridAnalysis.js's already-
//    proven `/api/v2/overview/{sha256}` GET (confirmed live with a real key,
//    see that file's own header comment on the deprecated search/hash
//    endpoint). That endpoint is a lookup only -- no behavioral report
//    fields (network/processes/dropped files) are available from it, same
//    limitation server/investigation/hashModule.js already discloses via
//    `behavior.detailedBehaviorAvailable: false`. Reported honestly here too
//    via `incomplete: true` rather than fabricating those fields.
//  - New URL submission: POST `/api/v2/submit/url` (Falcon Sandbox
//    environment-based analysis, not the overview endpoint), then poll
//    `/api/v2/report/{job_id}/state` until it leaves the queue, then read
//    `/api/v2/report/{job_id}/summary` for the full behavioral report. Field
//    names below follow Hybrid Analysis's documented v2 report-summary
//    schema; every array/object field is read defensively (Array.isArray
//    guards, optional chaining, no throwing on a missing/renamed field) so
//    an unexpected response shape degrades to an honestly-"incomplete"
//    report instead of crashing the whole submission -- this has NOT yet
//    been exercised against a real submitted job (submitting a live URL
//    consumes the account's sandbox quota), so treat the exact field
//    mapping as best-effort until verified against one real completed job.
import { ApiError, fetchJson } from "../../lib/http.js";
import { checkIndicator as checkHashOverview } from "../../lookups/hybridAnalysis.js";
import { withRetry } from "../../lib/retry.js";

// No "www." -- that subdomain does not serve this API (confirmed live: it
// 404s locally and appears to 403 from some networks/WAF paths, e.g.
// DigitalOcean's egress), while the bare apex domain works and is what
// Hybrid Analysis's own docs document as the base URL.
const BASE_URL = "https://hybrid-analysis.com/api/v2";
// A public Falcon Sandbox Windows 10 64-bit environment -- the standard
// default environment ID Hybrid Analysis documents for community/free-tier
// URL submissions.
const DEFAULT_ENVIRONMENT_ID = "160";

function apiKey() {
  const key = process.env.HYBRID_ANALYSIS_API_KEY;
  if (!key) throw new ApiError("Hybrid Analysis requires a free API key from hybrid-analysis.com (set HYBRID_ANALYSIS_API_KEY on the server)", "Hybrid Analysis", 401);
  return key;
}

function headers(extra = {}) {
  return { "api-key": apiKey(), "user-agent": "Falcon Sandbox", ...extra };
}

function toVerdict(rawVerdict, threatScore) {
  const v = (rawVerdict ?? "").toString().toLowerCase();
  if (v === "malicious" || (typeof threatScore === "number" && threatScore >= 70)) return "malicious";
  if (v === "suspicious" || (typeof threatScore === "number" && threatScore >= 30)) return "suspicious";
  if (v === "no verdict" || v === "no specific threat" || v === "whitelisted" || threatScore === 0) return "clean";
  return "unknown";
}

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

/**
 * Maps a `/api/v2/report/{id}/summary` response to a SandboxReport. Every
 * sub-field is read defensively -- see file header. `incomplete` is set
 * whenever a majority of the behavioral field groups came back empty, so
 * the UI/actionability layer can tell "genuinely benign, nothing observed"
 * apart from "the response just didn't have this data".
 * @returns {import("../../../src/types/threat-intel.js").SandboxReport}
 */
function normalizeSummary(jobId, raw) {
  const threatScore = typeof raw?.threat_score === "number" ? raw.threat_score : null;
  const networkConnections = safeArray(raw?.hosts)
    .map((h) => (typeof h === "string" ? { ip: h, port: null, protocol: null } : { ip: h?.host ?? h?.ip ?? null, port: h?.port ?? null, protocol: h?.protocol ?? h?.protocol_name ?? null }))
    .filter((c) => c.ip);
  const dnsQueries = safeArray(raw?.domains)
    .map((d) => (typeof d === "string" ? { domain: d, recordType: null } : { domain: d?.domain ?? d?.host ?? null, recordType: d?.type ?? null }))
    .filter((d) => d.domain);
  const httpRequests = safeArray(raw?.http_requests ?? raw?.network_requests)
    .map((r) => ({ url: r?.url ?? r?.uri ?? null, method: r?.method ?? null }))
    .filter((r) => r.url);
  const filesDropped = safeArray(raw?.extracted_files)
    .map((f) => ({ name: f?.name ?? null, sha256: f?.sha256 ?? null, path: f?.file_path ?? f?.path ?? null }))
    .filter((f) => f.name || f.sha256);
  const processes = safeArray(raw?.processes)
    .map((p) => ({ name: p?.name ?? null, commandLine: p?.command_line ?? p?.commandLine ?? null, pid: p?.pid ?? null, parentPid: p?.parentuid != null ? p.parentuid : (p?.parent_pid ?? null) }))
    .filter((p) => p.name || p.commandLine);
  const persistenceIndicators = safeArray(raw?.classification_tags ?? raw?.signatures)
    .map((s) => (typeof s === "string" ? s : (s?.name ?? s?.label ?? null)))
    .filter((s) => s && /persist|autorun|registry run|scheduled task|service install/i.test(s));
  const mitreAttackTechniques = safeArray(raw?.mitre_attcks)
    .map((m) => ({ id: m?.technique ?? m?.attck_id ?? m?.id ?? null, name: m?.tactic ?? m?.malicious_identifiers_count != null ? (m?.technique_name ?? null) : (m?.name ?? null), tactic: m?.tactic ?? null }))
    .filter((m) => m.id);
  const additionalIocs = {
    ips: networkConnections.map((c) => c.ip),
    domains: dnsQueries.map((d) => d.domain),
    urls: httpRequests.map((r) => r.url),
    hashes: filesDropped.map((f) => f.sha256).filter(Boolean),
  };
  const populatedGroups = [networkConnections, dnsQueries, filesDropped, processes, mitreAttackTechniques].filter((g) => g.length > 0).length;

  return {
    provider: "Hybrid Analysis",
    jobId,
    sha256: raw?.sha256 ?? null,
    verdict: toVerdict(raw?.verdict, threatScore),
    verdictLabel: raw?.verdict ?? null,
    threatScore,
    analyzedAt: raw?.analysis_start_time ?? null,
    environment: raw?.environment_description ?? null,
    malwareFamily: raw?.vx_family ?? null,
    executionObserved: Boolean(raw?.type_short === "url" ? processes.length > 0 || networkConnections.length > 0 : true),
    networkConnections,
    dnsQueries,
    httpRequests,
    filesDropped,
    processes,
    persistenceIndicators,
    mitreAttackTechniques,
    additionalIocs,
    relatedSamples: safeArray(raw?.similar_samples ?? raw?.related_samples).map((s) => (typeof s === "string" ? s : s?.sha256)).filter(Boolean),
    reportUrl: raw?.sha256 ? `https://hybrid-analysis.com/sample/${raw.sha256}` : null,
    incomplete: populatedGroups < 2,
  };
}

/**
 * Existing-hash check only -- never submits anything. See file header.
 * @returns {Promise<import("../../../src/types/threat-intel.js").SandboxReport | null>} null when HA has no report for this hash (404), never throws for "not found".
 */
async function checkExistingHash(sha256) {
  try {
    const r = await checkHashOverview("hash", sha256);
    return {
      provider: "Hybrid Analysis",
      jobId: sha256,
      sha256,
      verdict: r.verdict,
      verdictLabel: r.verdictLabel,
      threatScore: r.threatScore,
      analyzedAt: null,
      environment: null,
      malwareFamily: r.malwareFamily,
      executionObserved: true,
      networkConnections: [],
      dnsQueries: [],
      httpRequests: [],
      filesDropped: [],
      processes: [],
      persistenceIndicators: [],
      mitreAttackTechniques: [],
      additionalIocs: { ips: [], domains: [], urls: [], hashes: [] },
      relatedSamples: [],
      reportUrl: `https://hybrid-analysis.com/sample/${sha256}`,
      incomplete: true, // the overview endpoint never carries behavioral detail -- see file header
    };
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

/** @returns {Promise<{ jobId: string, submittedAt: string }>} */
async function submitUrl(url) {
  const form = new URLSearchParams({ url, environment_id: DEFAULT_ENVIRONMENT_ID });
  const raw = await withRetry(
    () =>
      fetchJson(`${BASE_URL}/submit/url`, {
        method: "POST",
        source: "Hybrid Analysis",
        headers: headers({ "Content-Type": "application/x-www-form-urlencoded" }),
        body: form.toString(),
        timeoutMs: 20_000,
      }),
    { retries: 2, isRetryable: (e) => e.status == null || e.status >= 500 }, // never retry a 4xx (bad key, bad URL, already-queued) -- only transient network/5xx
  );
  const jobId = raw?.job_id ?? raw?.id;
  if (!jobId) throw new ApiError("Hybrid Analysis submission did not return a job id", "Hybrid Analysis", 502);
  return { jobId, submittedAt: new Date().toISOString() };
}

/**
 * One poll of an in-flight job. Never throws on "still queued" -- that's
 * `status: "in_progress"`, not an error.
 * @returns {Promise<{ status: "in_progress" | "completed" | "failed", report: import("../../../src/types/threat-intel.js").SandboxReport | null, error: string | null }>}
 */
async function pollStatus(jobId) {
  let state;
  try {
    state = await fetchJson(`${BASE_URL}/report/${jobId}/state`, { source: "Hybrid Analysis", headers: headers(), timeoutMs: 15_000 });
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return { status: "in_progress", report: null, error: null }; // job registered but not yet queryable
    throw error;
  }
  const raw = (state?.state ?? "").toString().toUpperCase();
  if (raw === "IN_QUEUE" || raw === "IN_PROGRESS" || raw === "") return { status: "in_progress", report: null, error: null };
  if (raw === "ERROR") return { status: "failed", report: null, error: state?.error ?? "Hybrid Analysis reported analysis error" };

  const summary = await fetchJson(`${BASE_URL}/report/${jobId}/summary`, { source: "Hybrid Analysis", headers: headers(), timeoutMs: 15_000 });
  return { status: "completed", report: normalizeSummary(jobId, summary), error: null };
}

export default {
  id: "hybrid-analysis",
  label: "Hybrid Analysis",
  checkExistingHash,
  submitUrl,
  pollStatus,
};
