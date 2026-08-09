// File Hash (SHA256/SHA1/MD5) investigation module. Reuses VirusTotal +
// Hybrid Analysis + Team Cymru MHR verbatim. Behavior (registry/persistence/
// dropped files/mutexes/contacted IPs-domains) is only populated when Hybrid
// Analysis actually has a matching sandboxed report -- VirusTotal's free
// tier doesn't expose full behavioral reports, so this is explicitly gated
// rather than silently empty with no explanation.
import { checkIndicator as checkOtx } from "../connectors/otx.js";
import { checkIndicator as checkVirusTotal } from "../lookups/virustotal.js";
import { checkIndicator as checkHybridAnalysis } from "../lookups/hybridAnalysis.js";
import { checkIndicator as checkTeamCymru } from "../lookups/teamCymru.js";
import { throttleAndCache } from "../lib/lookupLimiter.js";
import { checkMispWarninglists } from "./mispCheck.js";

const LOOKUPS = [
  checkOtx,
  throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
  throttleAndCache("Hybrid Analysis", 5_000, checkHybridAnalysis),
  throttleAndCache("Team Cymru", 1_000, checkTeamCymru),
  checkMispWarninglists,
];

export const type = "hash";

export async function gather(value, hashKind) {
  const settled = await Promise.allSettled(LOOKUPS.map((fn) => fn("hash", value)));
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

  const vt = results.find((r) => r.source === "VirusTotal") ?? null;
  const ha = results.find((r) => r.source === "Hybrid Analysis") ?? null;
  const cymru = results.find((r) => r.source === "Team Cymru MHR") ?? null;

  const fileInfo = vt
    ? { fileType: vt.fileType ?? null, fileName: vt.fileName ?? null, firstSubmitted: vt.firstSubmitted ?? null, hashAlgorithm: hashKind.toUpperCase() }
    : { fileType: null, fileName: null, firstSubmitted: null, hashAlgorithm: hashKind.toUpperCase() };

  const detection = vt
    ? { malicious: vt.malicious ?? 0, suspicious: vt.suspicious ?? 0, harmless: vt.harmless ?? 0, threatLabel: vt.threatLabel ?? null }
    : null;

  const behavior = ha
    ? {
        available: true,
        malwareFamily: ha.malwareFamily ?? null,
        threatScore: ha.threatScore ?? null,
        verdictLabel: ha.verdictLabel ?? null,
        // Hybrid Analysis's free /search/hash endpoint (this app's only HA
        // integration) doesn't return the deep behavioral report fields --
        // registry keys, persistence, dropped files, mutexes, contacted
        // IPs/domains would need its paid Falcon Sandbox report API, which
        // this app doesn't have a key for. Reported honestly rather than
        // fabricated.
        detailedBehaviorAvailable: false,
        detailedBehaviorNote: "Hybrid Analysis matched this hash, but full behavioral detail (registry/persistence/dropped files/mutexes/contacted hosts) requires its paid Falcon Sandbox report API, not configured here.",
      }
    : { available: false, reason: "No matching Hybrid Analysis sandbox report found for this hash." };

  const malwareFamily = ha?.malwareFamily || vt?.threatLabel || null;
  // Which source actually produced the classification -- threaded through to
  // investigationGraph.js so a live-detected-family graph edge can cite the
  // real source instead of a vague "VirusTotal / Hybrid Analysis" guess.
  const malwareFamilySource = ha?.malwareFamily ? "Hybrid Analysis" : vt?.threatLabel ? "VirusTotal" : null;

  return {
    lookupResults: results,
    notConfigured,
    rateLimited,
    skipped,
    fileInfo,
    detection,
    malwareFamily,
    malwareFamilySource,
    behavior,
    registryHistory: cymru ? { detectionPercent: cymru.detectionPercent ?? null, lastSeen: cymru.lastSeen ?? null } : null,
  };
}
