// In-memory async job wrapper around generateInvestigationAiReport() -- lets
// POST /investigate/ai-report/start return instantly instead of blocking on
// the full AI call. Needed because DigitalOcean App Platform's own edge/
// load-balancer enforces a request timeout well under a minute, and a
// synchronous multi-provider-failover AI generation can legitimately exceed
// that even on a genuine success (a single large-schema Anthropic completion
// alone measured ~39s in testing) -- the platform kills the connection
// before the app ever gets to respond, surfacing as a 502/504 with no useful
// error. GET /investigate/ai-report/status is polled from the frontend until
// the job resolves, exactly the submit+poll shape server/sandboxIntelligence.js
// already uses for the same class of problem -- just in-memory and much
// shorter-lived (seconds to roughly a minute, never needs to survive a
// server restart, so no JSON persistence like the sandbox store has).
import { randomUUID } from "node:crypto";
import { investigate } from "./index.js";
import { generateInvestigationAiReport } from "../investigationAi.js";

const JOBS = new Map();
const JOB_TTL_MS = 10 * 60 * 1000;

function pruneOldJobs() {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of JOBS) {
    if (job.startedAt < cutoff) JOBS.delete(id);
  }
}

/** Kicks off generation in the background and returns immediately with a jobId to poll. */
export function startAiReportJob(query) {
  pruneOldJobs();
  const jobId = randomUUID();
  JOBS.set(jobId, { status: "pending", startedAt: Date.now() });

  (async () => {
    try {
      const investigation = await investigate(query);
      const report = await generateInvestigationAiReport(investigation);
      JOBS.set(jobId, { status: "complete", report, startedAt: Date.now() });
    } catch (error) {
      JOBS.set(jobId, { status: "failed", error: error.message, startedAt: Date.now() });
    }
  })();

  return jobId;
}

/** Returns the current job record, or null if the jobId is unknown/expired. */
export function getAiReportJob(jobId) {
  return JOBS.get(jobId) ?? null;
}
