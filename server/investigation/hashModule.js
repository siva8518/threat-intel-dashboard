// File Hash (SHA256/SHA1/MD5) investigation module. Reuses VirusTotal +
// Hybrid Analysis + Team Cymru MHR verbatim. Behavior (registry/persistence/
// dropped files/mutexes/contacted IPs-domains) is only populated when Hybrid
// Analysis actually has a matching sandboxed report -- VirusTotal's free
// tier doesn't expose full behavioral reports, so this is explicitly gated
// rather than silently empty with no explanation.
//
// Cross-hash enrichment (Team Cymru MHR only accepts MD5/SHA1 -- its DNS-
// zone lookup format hard-fails on a 64-char SHA256 label, see
// teamCymru.js's own comment): rather than skipping Team Cymru as "not
// applicable" for a SHA256 IOC, this module uses the SAME file's own MD5/
// SHA1 -- as reported by VirusTotal in the very same lookup, since VirusTotal
// computes and stores all three hash algorithms for every file in its corpus
// -- to query Team Cymru instead. This is a real, provider-reported
// association for the exact same file, never a mathematical conversion
// between hash algorithms (which is cryptographically impossible -- hashes
// are one-way). See buildCrossHashEnrichmentNote() below for the exact
// terminology this module always uses to describe it.
import { checkIndicator as checkOtx } from "../connectors/otx.js";
import { checkIndicator as checkVirusTotal } from "../lookups/virustotal.js";
import { checkIndicator as checkHybridAnalysis } from "../lookups/hybridAnalysis.js";
import { checkIndicator as checkTeamCymru } from "../lookups/teamCymru.js";
import { throttleAndCache } from "../lib/lookupLimiter.js";
import { checkMispWarninglists } from "./mispCheck.js";

const cymruLookup = throttleAndCache("Team Cymru", 1_000, checkTeamCymru);

const INDEPENDENT_LOOKUPS = [
  checkOtx,
  throttleAndCache("VirusTotal", 15_000, checkVirusTotal),
  throttleAndCache("Hybrid Analysis", 5_000, checkHybridAnalysis),
  checkMispWarninglists,
];

export const type = "hash";

function buildCrossHashEnrichmentNote(discoveredHashType, discoveredHash) {
  return `Team Cymru MHR only accepts MD5/SHA1 (a SHA256 hex string exceeds DNS's label length limit). This file's own ${discoveredHashType.toUpperCase()} -- ${discoveredHash} -- was cross-referenced from VirusTotal's own file record for this exact SHA256 (related hash discovered via cross-hash enrichment, not mathematically derived, since cryptographic hashes cannot be converted between algorithms) and used to query Team Cymru MHR instead.`;
}

export async function gather(value, hashKind) {
  // Team Cymru only runs directly in this first parallel batch when the
  // submitted hash is already MD5/SHA1 -- for SHA256 it has to wait for
  // VirusTotal's response first (see below), so it's deliberately excluded
  // from INDEPENDENT_LOOKUPS and handled separately in both cases.
  const parallelLookups = hashKind === "sha256" ? INDEPENDENT_LOOKUPS : [...INDEPENDENT_LOOKUPS, cymruLookup];

  const settled = await Promise.allSettled(parallelLookups.map((fn) => fn("hash", value)));
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
  let cymru = results.find((r) => r.source === "Team Cymru MHR") ?? null;
  let crossHashEnrichment = null;

  if (hashKind === "sha256" && !cymru) {
    const discoveredHashType = vt?.relatedHashes?.sha1 ? "sha1" : vt?.relatedHashes?.md5 ? "md5" : null;
    const discoveredHash = discoveredHashType === "sha1" ? vt.relatedHashes.sha1 : discoveredHashType === "md5" ? vt.relatedHashes.md5 : null;
    if (discoveredHash) {
      try {
        const cymruRaw = await cymruLookup("hash", discoveredHash);
        const note = buildCrossHashEnrichmentNote(discoveredHashType, discoveredHash);
        // Tagged onto the result itself (not just the module-level
        // registryHistory field below) so evidence.js's teamCymruMhrRule can
        // surface the same provenance directly on the Evidence Card -- an
        // analyst reading that card alone should never see a bare Team
        // Cymru finding with no indication it was queried by a different
        // hash than the one they submitted.
        cymru = { ...cymruRaw, crossHashEnrichmentNote: note };
        results.push(cymru);
        crossHashEnrichment = { discoveredHashType, discoveredHash, discoveredVia: "VirusTotal", note };
      } catch (error) {
        if (error?.status === 401) notConfigured.push(error.source);
        else if (error?.status === 429) rateLimited.push(error.source);
        else skipped.push({ source: error?.source ?? "Team Cymru MHR", reason: error?.message ?? "Lookup failed" });
      }
    } else {
      skipped.push({ source: "Team Cymru MHR", reason: "Only supports MD5/SHA1; no related MD5/SHA1 for this exact file could be cross-referenced from other configured sources (VirusTotal has no record of this SHA256)." });
    }
  }

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
    registryHistory: cymru ? { detectionPercent: cymru.detectionPercent ?? null, lastSeen: cymru.lastSeen ?? null, crossHashEnrichment } : null,
  };
}
