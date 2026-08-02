// Domain investigation module. Reputation reuses this app's existing domain
// lookups verbatim; Registration/DNS/Email-Security are new but entirely
// free/keyless (RDAP, Node's dns module); typosquat/homograph/DGA/parked
// heuristics are honestly-labeled algorithmic best-effort, not a live feed.
import { checkIndicator as checkOtx, getPassiveDns } from "../connectors/otx.js";
import { checkIndicator as checkPulsedive } from "../connectors/pulsedive.js";
import { checkIndicator as checkVirusTotal } from "../lookups/virustotal.js";
import { checkIndicator as checkLeakix } from "../lookups/leakix.js";
import { checkIndicator as checkCrtsh } from "../lookups/crtsh.js";
import { checkIndicator as checkHudsonRock } from "../lookups/hudsonRock.js";
import { checkIndicator as checkRdap } from "../lookups/rdap.js";
import { throttleAndCache } from "../lib/lookupLimiter.js";
import { checkMispWarninglists } from "./mispCheck.js";
import { resolveDnsRecords, resolveEmailSecurity } from "../lib/dnsRecords.js";
import { checkTyposquatting, checkDgaLikelihood, checkParkedOrDisposable } from "./domainHeuristics.js";
import { computeIocVerdict } from "./verdict.js";

const LOOKUPS = [
  checkOtx,
  throttleAndCache("Pulsedive", 3_000, checkPulsedive),
  throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
  throttleAndCache("LeakIX", 5_000, checkLeakix),
  throttleAndCache("crt.sh", 3_000, checkCrtsh),
  throttleAndCache("Hudson Rock", 3_000, checkHudsonRock),
  throttleAndCache("RDAP", 3_000, checkRdap),
  checkMispWarninglists,
];

export const type = "domain";

export async function gather(value) {
  const settled = await Promise.allSettled(LOOKUPS.map((fn) => fn("domain", value)));
  const results = [];
  const notConfigured = [];
  const rateLimited = [];
  const skipped = [];
  for (const outcome of settled) {
    if (outcome.status === "fulfilled") results.push(outcome.value);
    else if (outcome.reason?.status === 401) notConfigured.push(outcome.reason.source);
    else if (outcome.reason?.status === 429) rateLimited.push(outcome.reason.source);
    else if (outcome.reason?.source) skipped.push({ source: outcome.reason.source, reason: outcome.reason.message ?? "Lookup failed" });
  }

  const [dnsRecords, emailSecurity, passiveDnsResult] = await Promise.allSettled([
    resolveDnsRecords(value),
    resolveEmailSecurity(value),
    getPassiveDns("domain", value),
  ]);

  const registration = results.find((r) => r.source === "RDAP") ?? null;
  const certificate = results.find((r) => r.source === "crt.sh") ?? null;

  return {
    lookupResults: results.filter((r) => r.source !== "RDAP"), // RDAP is registration data, shown in its own section, not Source Breakdown noise
    notConfigured,
    rateLimited,
    skipped,
    registration,
    dnsRecords: dnsRecords.status === "fulfilled" ? dnsRecords.value : null,
    emailSecurity: emailSecurity.status === "fulfilled" ? emailSecurity.value : null,
    certificate,
    passiveDns:
      passiveDnsResult.status === "fulfilled"
        ? { available: true, records: passiveDnsResult.value }
        : { available: false, reason: passiveDnsResult.reason?.status === 401 ? "OTX_API_KEY not configured" : (passiveDnsResult.reason?.message ?? "Lookup failed") },
    security: {
      typosquatting: checkTyposquatting(value),
      dga: checkDgaLikelihood(value),
      parkedOrDisposable: checkParkedOrDisposable(value),
    },
    verdict: computeIocVerdict(results.filter((r) => r.source !== "RDAP")),
  };
}
